from yara import compile #pip install yara-python
from pathlib import Path
import os


# Análise de vírus com o Yara
def scan_file(file_name):
        file_path = f"{os.getcwd()}/files/{file_name}"

        if not os.path.exists(file_path):
            return print("O Arquivo não existe no diretório")
        
        all_yara_rules = to_rule_list(f"{os.getcwd()}/yara_rules", regex='*.yar')
        print(f"Iniciando a análise do arquivo {file_path} com as regras Yara.")
        for yara_rule in all_yara_rules:
            matches = yara_scan(str(yara_rule), file_path)
            if(matches != []):
                print("Arquivo malicioso! Vírus: " + str(matches[0]))
                return
            
        print("Arquivo Limpo!")    
        return 

#Obtem todas as regras Yara do diretório
def to_rule_list(path: str, regex: str = '*') -> [Path]:
    path_obj = Path(path)

    if path_obj.is_dir():
        return [file.resolve() for file in path_obj.rglob(regex) if file.is_file()]

    return [path_obj.resolve()]

#Realiza a verifição do arquivo com as regras Yara
def yara_scan(yara_rule_path: str, file_path):
    dummy = ""

    yara_rule = compile(yara_rule_path, externals={
                'filename': dummy,
                'filepath': dummy,
                'extension': dummy,
                'filetype': dummy,
                'md5': dummy
            })

    matches = yara_rule.match(file_path)
    return matches

