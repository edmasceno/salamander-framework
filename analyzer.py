import os
import argparse
import hashlib
import json
from datetime import datetime

class SalamandraAnalyzer:
    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.report = {
            "metadata": {
                "scan_time": datetime.now().isoformat(),
                "target_directory": target_dir,
                "total_files_scanned": 0
            },
            "ignored_files": 0,
            "suspicious_files": []
        }

    def _get_hashes(self, file_path):
        """
        Calcula MD5 e SHA256 em chunks (blocos) para não estourar a memória RAM,
        mesmo se o arquivo for grande.
        """
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        
        try:
            # Modo 'rb' (read-binary): o arquivo é lido como bytes, impossível de ser executado acidentalmente.
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
            return md5.hexdigest(), sha256.hexdigest()
        except PermissionError:
            return "Acesso Negado", "Acesso Negado"
        except Exception as e:
            return f"Erro: {str(e)}", f"Erro: {str(e)}"

    def scan(self):
        """Varre o diretório alvo."""
        print(f"[*] Salamandra ativada. Escaneando diretório: {self.target_dir}")
        
        if not os.path.exists(self.target_dir):
            print("[-] Erro: Diretório não encontrado.")
            return

        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                self.report["metadata"]["total_files_scanned"] += 1
                
                # Por enquanto, vamos apenas calcular os hashes de tudo que entrar
                md5_hash, sha256_hash = self._get_hashes(file_path)
                
                print(f"[+] Arquivo lido: {file} | SHA256: {sha256_hash}")
                
                # A lógica de classificar se é suspeito ou ignorado entrará aqui depois
                self.report["ignored_files"] += 1 

    def export_report(self, output_name="salamandra_report.json"):
        """Gera o veredito final em JSON."""
        with open(output_name, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=4, ensure_ascii=False)
        print(f"\n[v] Relatório gerado com sucesso: {output_name}")

if __name__ == "__main__":
    # Configuração da Linha de Comando (CLI)
    parser = argparse.ArgumentParser(description="Salamandra Framework - Batch Triage & Malware Pre-Filter")
    parser.add_argument("-t", "--target", required=True, help="Caminho da pasta a ser analisada (Ex: C:\\Amostras)")
    
    args = parser.parse_args()
    
    # Inicializa a classe e roda o fluxo
    analyzer = SalamandraAnalyzer(args.target)
    analyzer.scan()
    analyzer.export_report()
