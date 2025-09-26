# AI-Hunting

# Manual de uso — AI Hunting (Resumo rápido)

[![Assista ao vídeo](https://img.youtube.com/vi/11sqkThyr_Q/0.jpg)](https://www.youtube.com/watch?v=11sqkThyr_Q)

## 1. Visão geral

* Os scripts criam um diretório de logs na sua área de trabalho: `%USERPROFILE%\Desktop\threat_hunt_YYYY-MM-DD_HH-mm-ss`.
* Geram um relatório Excel: `threat_hunt_report.xlsx`.
* Criam uma pasta de quarentena dentro do diretório de logs: `quarantine`.
* Exigem execução como Administrador e PowerShell 7 (pwsh). Se pwsh não existir, tentam instalar via `winget`.
* Chamam um módulo em `modules\ai-hunting.ps1` (verifique se existe e tem permissões).

## 2. Requisitos

* Windows 10/11 atualizado.
* Conta com privilégios de Administrador (ou capacidade de elevar).
* PowerShell 7 (pwsh) preferencial — mas funcionam também em Windows PowerShell se adaptados.
* Winget disponível (para instalação automática do PowerShell 7, se necessário).
* Diretório `modules\` com `ai-hunting.ps1` presente no mesmo diretório dos scripts.

## 3. Preparação (permissões e política de execução)

Executar PowerShell como Administrador e rodar os comandos abaixo conforme o nível desejado.

1. Permitir execução **temporária** apenas na sessão atual (recommended for testing):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\caminho\para\ai-hunting.ps1"
```

2. Definir política para o usuário atual (recomendado se for uso contínuo):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

3. Definir política para a máquina inteira (requer Admin; menos seguro):

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

4. Desbloquear arquivo baixado (se necessário):

```powershell
Unblock-File -Path "C:\caminho\para\ai-hunting.ps1"
```

5. Rodar um script **elevado** (executa como Administrador via UAC prompt):

```powershell
Start-Process pwsh -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',"C:\caminho\para\ai-hunting.ps1"
```

6. Instalar PowerShell 7 (se `pwsh` não existir):

```powershell
winget install --id Microsoft.PowerShell --source winget --silent
```

7. Para desenvolvimento/testes — executar com bypass apenas na sessão (não muda política permanente):

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File "C:\caminho\para\ai-hunting.ps1"
```

## 4. Como executar (exemplos práticos)

* Executar normalmente (PowerShell 5.x):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\scripts\ai-hunting.ps1"
```

* Executar com pwsh (PowerShell 7+):

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File "C:\scripts\ai-hunting.ps1"
```

* Executar com elevação (abrir janela elevada automaticamente):

```powershell
Start-Process pwsh -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File "C:\scripts\ai-hunting.ps1"'
```

## 5. Agendamento (ex.: agendar via Task Scheduler)

* Agendar com `schtasks` (executa diariamente às 02:00 com privilégios elevados):

```powershell
schtasks /Create /SC DAILY /TN "AI-Hunting" /TR "pwsh -NoProfile -ExecutionPolicy Bypass -File \"C:\scripts\ai-hunting.ps1\"" /ST 02:00 /RL HIGHEST /F
```

## 6. Executar em background (serviço / NSSM)

* Recomendo NSSM para transformar em serviço:

1. Baixe nssm.exe e copie para `C:\nssm\nssm.exe`.
2. Instale serviço:

```powershell
C:\nssm\nssm.exe install AIHunting "C:\Program Files\PowerShell\7\pwsh.exe" "-NoProfile -ExecutionPolicy Bypass -File \"C:\scripts\ai-hunting.ps1\""
C:\nssm\nssm.exe start AIHunting
```

## 7. Parâmetros e logs

* O script cria diretório `threat_hunt_YYYY-MM-DD_HH-mm-ss` no Desktop do usuário e gera:

  * `threat_hunt_report.xlsx`
  * `quarantine\` contendo arquivos movidos para quarentena
* Verifique variáveis no topo do script: ` $logDir`, `$outputExcel`, `$quarantineDir`, `$scriptStartTime`.

## 8. Boas práticas e segurança

* Verifique conteúdo de `modules\ai-hunting.ps1` antes de rodar (audit).
* Execute primeiro em ambiente isolado (máquina de teste) antes de produção.
* Não defina `ExecutionPolicy` como `Unrestricted` globalmente em máquinas de produção.
* Considere assinar o script com um certificado se for implantar em vários hosts:

  * Gerar certificado self-signed e assinar com `Set-AuthenticodeSignature`.
* Backup dos logs antes de limpeza automática.
* Se o script interage com rede/Internet, avalie regras de firewall e proxy.

## 9. Tratamento de erros comuns

* **Erro de permissão / Admin required** — abra PowerShell como Administrador ou use `Start-Process -Verb RunAs`.
* **pwsh: comando não encontrado** — instale PowerShell 7 com `winget` (ou ajuste para `powershell.exe`).
* **Módulo não encontrado (`modules\ai-hunting.ps1`)** — confirme que existe `modules` no mesmo diretório do script e que o arquivo possui permissões de leitura.
* **Antivírus bloqueou** — revise detecção; não desative AV sem justificativa. Se for ferramenta interna, coloque em whitelist aprovada.
* **Falha ao criar Excel** — verifique dependências (se usa COM Excel, precisa ter Excel instalado; se usa módulo para gerar XLSX, certifique-se do módulo `ImportExcel`).

## 10. Exemplo completo (passo-a-passo rápido)

1. Copie os scripts para `C:\scripts`.
2. Abra PowerShell como Administrador.
3. Desbloqueie:

```powershell
Unblock-File -Path "C:\scripts\ai-hunting.ps1"
Unblock-File -Path "C:\scripts\setup.ps1"
```

4. Ajuste ExecutionPolicy para current user:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

5. Execute:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File "C:\scripts\ai-hunting.ps1"
```

6. Verifique a pasta `%USERPROFILE%\Desktop\threat_hunt_*` para relatórios e `quarantine`.

## 11. Como verificar se o script rodou e localizar saídas

* Abra Explorador → Desktop → procure `threat_hunt_` com timestamp.
* Abra `threat_hunt_report.xlsx` (Excel ou LibreOffice).
* Log do PowerShell (se implementado) — procure mensagens na saída do console; se quiser, modifique script para registrar um `run.log` dentro do `$logDir`.

