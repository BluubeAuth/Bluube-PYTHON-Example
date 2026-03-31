# Sistema de Autenticação Bluube - Exemplo em Python

Aplicativo de console em Python que demonstra a integração com o sistema de autenticação BluubeAuth, permitindo login e registro de usuários através de chaves de licença ou credenciais de usuário.

## 📋 Sobre o Projeto

Este projeto é um exemplo de implementação do BluubeAuth em uma aplicação Python com interface de console, oferecendo três métodos de autenticação:
- **Login com Usuário e Senha**: Autenticação tradicional com credenciais
- **Login com Chave de Licença**: Autenticação usando apenas uma chave de licença
- **Registro de Novo Usuário**: Criação de conta com usuário, senha e chave de licença

## 🛠️ Tecnologias Utilizadas

- **Python 3.7+** para desenvolvimento
- **requests** para comunicação HTTP rápida e estável
- **PyNaCl (Ed25519)** para verificação de chaves e assinaturas da API
- **Threading** para manter pulso de conexão contínuo (Heartbeat)
- **Interface de Console** interativa com menu de opções

## 📦 Dependências

O projeto utiliza os seguintes pacotes Python:

- **requests**: Cliente HTTP
- **pynacl**: Criptografia e validação de assinaturas Ed25519 digitais

As dependências estão listadas no arquivo `requirements.txt`.

## 🚀 Como Configurar

### Pré-requisitos

- Python 3.7 ou superior
- pip (gerenciador de pacotes Python)
- Conta na Bluube com AppID, OwnerID e Version configurados

### Instalação

1. Clone ou baixe este repositório
2. Instale as dependências necessárias:

```bash
pip install -r requirements.txt
```

Ou execute o script de instalação fornecido (Windows):
```bash
install_requirements.bat
```

3. Configure suas credenciais BluubeAuth no arquivo `main.py`:

```python
// APP_ID, OWNER_ID, VERSION
auth = BluubeAuth(app_id="SUA_APP", owner_id="SEU_OWNER_ID", version="1.0")
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
Python Example/
├── main.py                    # Arquivo principal (Interface do console)
├── BluubeAuth.py              # Classe principal do SDK com segurança Ed25519
├── requirements.txt           # Dependências do projeto
├── start.bat                  # Script de inicialização (Windows)
└── install_requirements.bat   # Script de instalação de dependências (Windows)
```

## 🔑 Funcionalidades

### BluubeAuth.py

A classe `BluubeAuth` fornece métodos poderosos e criptografados para lidar com autenticação:

- **`initialize()`**: Autentica seu aplicativo no servidor Bluube, recebendo tokens e validando assinaturas.
- **`register_with_key()`**: Registra um usuário consumindo uma chave/licença intacta.
- **`login_user()`**: Faz o login usando as novas credenciais criadas.
- **`logout()` / `close()`**: Finaliza a sessão e as instâncias secundárias.
- **`Heartbeat` Contínuo**: (Automático) Pulso de vida para garantir que a sessão continue válida após login.

### main.py (Interface de Console)

O programa oferece um menu interativo com as seguintes opções:

1. **Login com Usuário e Senha**: Autenticação com credenciais de usuário.
2. **Registrar Novo Usuário**: Registro de nova conta com usuário, senha e chave.
3. **Sair**: Encerra o programa.

### Características da Interface

- **Limpeza de tela**: Ao selecionar uma opção, a tela é limpa para melhor visualização.
- **Cabeçalho personalizado**: Exibe o título "BluubeAuth - Python Example" em cada tela.
- **Mensagens de sucesso/erro**: Feedback claro para o usuário sobre o resultado das operações.
- **User Data Integrado**: Você pode acessar facilmente todas as informações do usuário pós-login usando os dicionários em `auth.user_data` (como expiração, HWID, IP de acesso, etc).

## 🔒 Segurança

O sistema implementa as seguintes medidas de segurança:

- **Assinatura Ed25519 em Respostas**: Toda resposta do servidor é assinada digitalmente. O SDK intercepta a assinatura (`X-Bluube-Signature`) e verifica. Um atacante não pode emular a API com status 200, pois precisa possuir a chave privada.
- **Pinning de Chave Pública**: A chave pública do seu servidor é fixa no SDK. Impede falsificação pura da API em ataques "Man-in-the-Middle" (MITM).
- **Proteção Anti-Replay Timestamp**: Respostas têm timestamps assinados. Se uma resposta válida for atrasada ou reenviada pelo atacante fora da janela permitida, ela é negada.
- **Coleta de HWID Real**: Não se baseia só em IP. O sistema coleta de maneira sofisticada (via `advapi32` e SIDs de Windows nativo) garantindo exclusividade de máquina.
- **Heartbeat e Kill-Switch Ativo**: Conexões irregulares, bans ou mudanças de versão farão o seu aplicativo encerrar a si mesmo em tempo real.

## ⚙️ Configuração da API

A API BluubeAuth está configurada para usar o endpoint:
```
https://api.bluube.com
```

Certifique-se de que este endpoint está acessível e que suas credenciais (AppID, OwnerID e Version) estão corretas.

## 🐛 Tratamento de Erros e Segurança

Em caso de violações de segurança (por exemplo, tentativa boba de modificar o HTTP para sempre voltar resposta `success: true`), o console não lançará erros genéricos — ele emitirá a exceção estrutural interna `_terminate()` identificando a violação (falta de assinatura, carimbo de data corrompido ou erro na chave ed25519) e encerrará o processo imediatamente.

## ⚠️ Avisos

- **Nunca compartilhe suas credenciais** (AppID e OwnerID) publicamente
- **Use variáveis de ambiente** em produção para armazenar credenciais sensíveis
- **Implemente verificações de integridade** para prevenir modificações no código
- **Mantenha suas dependências atualizadas** para segurança
- **Use ofuscação de código** se necessário para proteger sua aplicação

## 📞 Suporte

Para questões sobre a Bluube, consulte a documentação oficial ou entre em contato com o suporte pelo discord.

---

**Nota**: Este é um projeto de exemplo educacional. Adapte-o conforme necessário para seu uso específico.
