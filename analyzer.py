import os
import argparse
import hashlib
import json
import zipfile
import tempfile
import yara
from datetime import datetime

class SalamandraAnalyzer:
    def __init__(self, target_dir):
        self.target_dir = target_dir
        self.rules_dir = "rules"
        self.yara_engine = self._load_yara_rules()
        self.report = {
            "metadata": {
                "scan_time": datetime.now().isoformat(),
                "target_directory": target_dir,
                "total_files_scanned": 0
            },
            "ignored_files": 0,
            "suspicious_files": []
        }

    def _load_yara_rules(self):
        """Compila todas as regras .yar da pasta rules/"""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            print("[i] Pasta 'rules' não encontrada. Criada automaticamente.")
            return None
        
        rule_files = {}
        for file in os.listdir(self.rules_dir):
            if file.endswith(('.yar', '.yara')):
                rule_files[file] = os.path.join(self.rules_dir, file)
                
        if not rule_files:
            print("[i] Nenhuma regra YARA encontrada na pasta 'rules'.")
            return None
            
        try:
            print(f"[*] Compilando {len(rule_files)} regra(s) YARA...")
            return yara.compile(filepaths=rule_files)
        except Exception as e:
            print(f"[-] Erro ao compilar regras YARA: {e}")
            return None

    def _get_hashes(self, file_path):
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
        try:
            with open(file_path, "rb") as f:
                header = f.read(4) 
            if header.startswith(b'MZ'): return "Windows_Executable"
            elif header.startswith(b'PK\x03\x04'): return "Zip_Jar_Archive"
            elif header.startswith(b'%PDF'): return "PDF_Document"
            elif header.startswith(b'\x7fELF'): return "Linux_Executable"
            else: return "Other"
        except Exception:
            return "Error"

    def _analyze_file(self, file_path, display_path=None):
        if display_path is None: display_path = file_path 
            
        self.report["metadata"]["total_files_scanned"] += 1
        md5_hash, sha256_hash = self._get_hashes(file_path)
        real_type = self._check_magic_bytes(file_path)
        _, ext = os.path.splitext(display_path)
        ext = ext.lower()

        is_suspicious = False
        motivo = ""
        is_nested = "->" in display_path

        # 1. Regras Base (Camuflagem e Droppers)
        if real_type == "Windows_Executable" and ext not in [".exe", ".dll"]:
            is_suspicious = True
            motivo = f"Camuflagem Detectada (Extensão {ext} falsa)."
        elif real_type == "Zip_Jar_Archive" and ext not in [".zip", ".jar", ".docx", ".xlsx"]:
            is_suspicious = True
            motivo = f"Camuflagem: Pacote oculto (Extensão {ext})."
        elif is_nested:
            suspicious_scripts = [".bat", ".ps1", ".vbs", ".js", ".wsf", ".cmd"]
            if real_type in ["Windows_Executable", "Linux_Executable"] or ext in suspicious_scripts:
                is_suspicious = True
                motivo = f"Dropper Detectado: Arquivo malicioso embutido no pacote."

        # 2. Motor YARA (Análise de Assinaturas)
        if self.yara_engine and not is_suspicious:
            try:
                yara_matches = self.yara_engine.match(file_path)
                if yara_matches:
                    is_suspicious = True
                    match_names = ", ".join([match.rule for match in yara_matches])
                    motivo = f"YARA Match: {match_names}"
            except Exception:
                pass

        if is_suspicious:
            print(f"[!] ALERTA: {display_path} - {motivo}")
            self.report["suspicious_files"].append({
                "nome": os.path.basename(display_path),
                "caminho": display_path, 
                "motivo": motivo,
                "sha256": sha256_hash
            })
        else:
            self.report["ignored_files"] += 1 
            
        # 3. Extração Efêmera
        if real_type == "Zip_Jar_Archive" and ext in [".zip", ".jar"] and not is_nested:
            self._process_archive(file_path, display_path)

    def _process_archive(self, archive_path, display_path):
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        extracted_file_path = os.path.join(root, file)
                        self._analyze_file(extracted_file_path, display_path=f"{display_path} -> {file}")
        except zipfile.BadZipFile:
            pass

    def scan(self):
        print(f"[*] Salamandra ativada. Escaneando: {self.target_dir}")
        if not os.path.exists(self.target_dir):
            print("[-] Erro: Diretório alvo não encontrado.")
            return
        for root, dirs, files in os.walk(self.target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                self._analyze_file(file_path)

    def export_report(self, output_name="salamandra_report.json"):
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
