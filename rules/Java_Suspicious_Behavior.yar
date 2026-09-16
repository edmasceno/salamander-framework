rule Java_Suspicious_Behavior {
    meta:
        author = "Ed"
        description = "Detecta artefatos Java com comportamento genérico de execução de comandos (Dropper), download suspeito e manipulação de arquivos (Timestomping)"
        date = "2026-09-16"
        threat_level = "High"
        category = "Detection Engineering"

    strings:
        // 1. Comandos de Execução no Sistema Operacional (Acesso à Shell)
        $exec_1 = "java/lang/ProcessBuilder"
        $exec_2 = "java/lang/Runtime"
        $exec_3 = "cmd.exe" nocase
        $exec_4 = "/bin/sh" nocase
        $exec_5 = "powershell" nocase

        // 2. Indicadores de Download / Comunicação de Rede
        $net_1 = "java/net/URL"
        $net_2 = "openStream"
        $net_3 = "HttpURLConnection"

        // 3. Indicadores de Gravação Oculta no Disco
        $drop_1 = "java/io/FileOutputStream"
        $drop_2 = "java/nio/file/Files"
        $drop_3 = "java.io.tmpdir" // Tentar gravar silenciosamente na pasta temporária

        // 4. Indicadores de Evasão (Manipulação de rastros)
        $evas_1 = "setLastModifiedTime"
        $evas_2 = "java/nio/file/attribute/FileTime"

    condition:
        // A lógica do SOC: 
        // Não apita para qualquer programa Java (evita falsos positivos).
        // Apita SE o código tentar executar comandos de sistema (exec) 
        // E tiver pelo menos mais um comportamento malicioso associado (evasão, rede ou gravação suspeita).
        
        (any of ($exec_*)) and (any of ($evas_*) or any of ($net_*) or 2 of ($drop_*))
}
