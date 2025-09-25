# src/preprocessing/parser.py
import pandas as pd
import json
import os

def parse_log(file_path: str) -> pd.DataFrame:
    """
    Parse un fichier de log et le convertit en DataFrame.
    Supporte : CSV, JSON, PCAP (via scapy), TXT.
    """
    ext = os.path.splitext(file_path)[-1].lower()

    if ext == ".csv":
        df = pd.read_csv(file_path)

    elif ext == ".json":
        with open(file_path, "r") as f:
            data = json.load(f)
        df = pd.json_normalize(data)

    elif ext == ".txt":
        # Exemple simple : logs séparés par des espaces
        df = pd.read_csv(file_path, sep=" ", header=None)

    elif ext == ".pcap":
        try:
            from scapy.all import rdpcap
        except ImportError:
            raise ImportError("Installe scapy pour traiter les fichiers pcap (pip install scapy)")

        packets = rdpcap(file_path)
        rows = []
        for pkt in packets:
            row = {
                "time": pkt.time,
                "src": pkt[0][1].src if hasattr(pkt[0][1], "src") else None,
                "dst": pkt[0][1].dst if hasattr(pkt[0][1], "dst") else None,
                "proto": pkt[0][1].proto if hasattr(pkt[0][1], "proto") else None,
                "len": len(pkt)
            }
            rows.append(row)
        df = pd.DataFrame(rows)

    else:
        raise ValueError(f"Format non supporté : {ext}")

    return df


if __name__ == "__main__":
    # Exemple d’utilisation
    fichier = "../../data/KDDTrain+.csv"
    logs = parse_log(fichier)
    print(logs.head())

