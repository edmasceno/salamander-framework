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
        """Calcula MD5 e SHA256 em chunks."""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
            return md5.hexdigest(), sha256.hexdigest()
        except Exception:
            return "Erro", "Erro"

    def _check_magic_bytes(self, file_path):
        """Lê o cabeçalho binário para descobrir a verdadeira identidade do arquivo."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(4) # Lê apenas os primeiros 4 bytes
            
            # Assinaturas Hexadecimais Conhecidas
            if header.startswith(b'MZ'):
                return "Windows_Executable"
            elif header.startswith(b'PK\x03\x04'):
                return "Zip_Jar_Archive"
            elif header.startswith(b'%PDF'):
                return "PDF_Document"
            elif header.startswith(b'\x7fELF'):
                return "Linux_Executable"
            else:
                return "Other"
        except Exception:
            return "Error"

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
                
                # Coleta Hashes e Identidade
                md5_hash, sha256_hash = self._get_hashes(file_path)
                real_type = self._check_magic_bytes(file_path)
                
                # Extrai a extensão declarada pelo arquivo
                _, ext = os.path.splitext(file)
                ext = ext.lower()

                # LÓGICA DE DETECÇÃO: O arquivo está mentindo?
                is_suspicious = False
                motivo = ""

                # Se o cabeçalho diz que é executável (MZ), mas a extensão NÃO é .exe ou .dll
                if real_type == "Windows_Executable" and ext not in [".exe", ".dll"]:
                    is_suspicious = True
                    motivo = f"Camuflagem Detectada: Arquivo se diz {ext}, mas é um executável oculto."
                
                # Se for um JAR/ZIP camuflado (Muitos ransomwares se escondem assim)
                elif real_type == "Zip_Jar_Archive" and ext not in [".zip", ".jar", ".docx", ".xlsx"]:
                    is_suspicious = True
                    motivo = f"Arquivo compactado oculto. Extensão declarada: {ext}."

                if is_suspicious:
                    print(f"[!] ALERTA: {file} - {motivo}")
                    self.report["suspicious_files"].append({
                        "nome": file,
                        "caminho": file_path,
                        "motivo": motivo,
                        "sha256": sha256_hash
                    })
                else:
                    self.report["ignored_files"] += 1 

    def export_report(self, output_name="salamandra_report.json"):
        """Gera o veredito final em JSON."""
        with open(output_name, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=4, ensure_ascii=False)
        print(f"\n[v] Relatório gerado: {output_name}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Salamandra Framework - Batch Triage & Malware Pre-Filter")
    parser.add_argument("-t", "--target", required=True, help="Caminho da pasta a ser analisada")
    args = parser.parse_args()
    
    analyzer = SalamandraAnalyzer(args.target)
    analyzer.scan()
    analyzer.export_report()
