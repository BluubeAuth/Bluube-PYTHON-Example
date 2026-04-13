# Sistema de Autenticação Bluube - Exemplo em Python

Aplicativo de console em Python que demonstra a integração com o BluubeAuth: **`initialize()`**, login com usuário e senha, registro com chave de licença e opção de sair. O arquivo `BluubeAuth.py` é o núcleo reutilizável do SDK.

## 📋 Sobre o Projeto

Este exemplo implementa o BluubeAuth em modo **console**, com menu interativo. O que o `main.py` oferece hoje:

- **Login com usuário e senha** — autenticação com credenciais já registradas.
- **Registrar novo usuário** — cria conta com chave de licença + usuário + senha.
- **Sair** — encerra o programa.

Você pode **estender o menu** (por exemplo, fluxo só com chave de licença) usando os mesmos métodos de `BluubeAuth`; isso fica a critério do seu produto.

## 💓 O heartbeat: o que é, por que existe e o que acontece se não estiver certo

Depois de um **`initialize()`** bem-sucedido, o SDK **inicia automaticamente** um pulso periódico (**heartbeat**) que chama o endpoint **`/heartbeat`** no servidor, enviando sessão, IP, versão e HWID quando aplicável.

**Por que isso importa**

- O servidor sabe que o cliente **continua vivo** e pode aplicar **políticas** (versão do app, bloqueios, HWID, VPN, etc.).
- Sessões **fantasma** ou **revogadas** são detectadas: a API pode responder com falha; em caso de mensagem **`Invalid session`** (inglês, conforme o contrato da API), o exemplo encerra o processo de forma controlada.
- Sem heartbeat bem implementado (ou se você **remover** o pulso e **não** substituir por nada), o servidor **não recebe** esses sinais: expiração por tempo, limpeza de sessão e regras de segurança **deixam de funcionar como o painel espera**. Na prática: usuário pode parecer “logado” localmente enquanto o servidor já invalidou a sessão, ou o contrário — comportamento inconsistente e suporte mais difícil.

**O que “implementado direito” significa neste exemplo**

- Não chamar heartbeat **só depois** do login se a sua API já exige sessão válida na tela inicial — por isso o exemplo inicia o heartbeat **logo após** o `initialize()`, inclusive **antes** do usuário logar.
- Manter o intervalo coerente com o servidor (aqui, por volta de **30 segundos** no código de exemplo).
- Em **depuração**: se você **pausar todo o processo** no depurador (“Break All”), timers e threads param — o heartbeat **não dispara** até continuar a execução. Isso é esperado; não indica bug em produção.

## 🛠️ Tecnologias Utilizadas

- **Python 3.7+** para desenvolvimento
- **requests** para comunicação HTTP rápida e estável
- **PyNaCl (Ed25519)** para verificação de chaves e assinaturas da API
- **Threading** para o heartbeat em segundo plano
- **Interface de console** interativa com menu de opções

## 📦 Dependências

O projeto utiliza os seguintes pacotes Python:

- **requests**: cliente HTTP
- **pynacl**: criptografia e validação de assinaturas Ed25519

As dependências estão listadas no arquivo `requirements.txt` (pasta `Console/`).

## 🚀 Como Configurar

### Pré-requisitos

- Python 3.7 ou superior
- pip (gerenciador de pacotes Python)
- Conta na Bluube com AppID, OwnerID e Version configurados

### Instalação

1. Clone ou baixe este repositório.
2. Entre na pasta **`Console/`** e instale as dependências:

```bash
pip install -r requirements.txt
```

Ou execute o script de instalação fornecido (Windows):

```bash
install_requirements.bat
```

3. Configure suas credenciais BluubeAuth no arquivo `main.py`:

```python
# APP_ID, OWNER_ID, VERSION
auth = BluubeAuth(app_id="APP_ID", owner_id="OWNER_ID", version="1.0")
```

4. Execute o programa:

```bash
python main.py
```

Ou use o script de inicialização (Windows):

```bash
start.bat
```

## 📁 Estrutura do Projeto

```
Bluube-PYTHON-Example/
├── README.md                          # Documentação
└── Console/
    ├── main.py                        # Arquivo principal (interface do console)
    ├── BluubeAuth.py                  # Classe principal do SDK com segurança Ed25519
    ├── requirements.txt               # Dependências do projeto
    ├── start.bat                      # Script de inicialização (Windows)
    └── install_requirements.bat       # Script de instalação de dependências (Windows)
```

## 🔑 Funcionalidades

### BluubeAuth.py

A classe `BluubeAuth` concentra a comunicação segura com a API:

- **`initialize()`**: registra o aplicativo no servidor, obtém a sessão e valida assinaturas; em seguida **inicia o heartbeat** automático (não é necessário chamar de novo após login/registro neste exemplo).
- **`register_with_key()`**: registra um usuário consumindo uma chave/licença.
- **`login_user()`**: login com usuário e senha.
- **`logout()` / `close()`**: encerra o heartbeat e limpa o estado da sessão.
- **Heartbeat**: ver a seção **O heartbeat** no início deste README; respostas com **`Invalid session`** encerram o processo com código 0, alinhado à API.

### main.py (Interface de Console)

Menu interativo:

1. Login com usuário e senha  
2. Registrar novo usuário (chave + usuário + senha)  
3. Sair  

### Características da Interface

- **Limpeza de tela** ao navegar no menu.
- **Cabeçalho** com o título do exemplo.
- **Mensagens** de sucesso ou erro claras.
- **Dados do usuário** após login/registro bem-sucedido via `auth.user_data` (expiração, HWID, IP, etc.).

## 🔒 Segurança

- **Assinatura Ed25519 em respostas**: o SDK verifica `X-Bluube-Signature` e `X-Bluube-Timestamp`; respostas forjadas sem a chave privada do servidor são rejeitadas.
- **Pinning de chave pública**: a chave esperada está fixa no código do exemplo.
- **Anti-replay** por janela de tempo no timestamp assinado.
- **HWID**: no Windows o exemplo usa camadas nativas (SID, registro, fallbacks); em Linux/macOS há estratégias alternativas no código.
- **Heartbeat**: mantém a sessão alinhada às regras do servidor; ver seção dedicada acima.

## ⚙️ Configuração da API

A API BluubeAuth está configurada para usar o endpoint:

```
https://api.bluube.com
```

Certifique-se de que o endpoint está acessível e que AppID, OwnerID e Version estão corretos no painel Bluube.

## 🐛 Tratamento de Erros e Segurança

Violações de integridade (assinatura inválida, resposta adulterada, etc.) disparam **`_terminate()`** com mensagem e encerramento do processo, em vez de seguir com estado inconsistente.

## ⚠️ Avisos

- **Nunca compartilhe** AppID e OwnerID publicamente.
- **Use variáveis de ambiente** ou cofres de segredos em produção.
- **Mantenha dependências atualizadas** (`pip`).
- **Ofuscação / integridade** do binário são responsabilidade do seu pipeline de release, se precisar.

## 📞 Suporte

Para questões sobre a Bluube, consulte a documentação oficial ou entre em contato com o suporte pelo discord.

---

**Nota**: Este é um projeto de exemplo educacional. Adapte-o conforme necessário para seu uso específico.
