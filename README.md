# Paloma Firewall & Intrusion Defense Dashboard (`paloma-fw`)

Painel de segurança e observabilidade para firewall, mitigação de intrusões e gestão do Fail2ban no servidor Paloma (`137.131.142.90`), integrado com a instância dedicada de **MySQL HeatWave da OCI** (`10.0.0.159:3306`).

## 🛡️ Características
- **Ultra-leve:** Desenvolvido em Go 1.25 puro, consumindo menos de 15MB de RAM e imagem Docker com ~25MB.
- **Gerenciado pelo Coolify:** Implantado diretamente via repositório GitHub com certificados SSL automáticos Let's Encrypt para `https://fw.potencial.tec.br`.
- **Persistência no MySQL HeatWave:** Armazena todos os eventos de banimento, desbanimento, tentativas e auditoria no banco `paloma_security`.
- **Migrações Automatizadas:** Sistema de migrações SQL nativo embutido no binário (`migrations/`), executado automaticamente na inicialização.
- **Integração Real-Time com Fail2ban:** Sincronização via webhook instantâneo e socket Unix (`/var/run/fail2ban/fail2ban.sock`).
- **Desbanimento Seguro em 1 Clique:** Validação estrita de IP (`net.ParseIP`), eliminando qualquer risco de injeção de comandos.
- **Design Impecável:** Interface moderna com tema escuro operacional, contraste acessível WCAG AAA (OKLCH), métricas em tempo real e atualização dinâmica.

## ⚙️ Variáveis de Ambiente
| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `PORT` | `3340` | Porta HTTP da aplicação |
| `DB_HOST` | `10.0.0.159` | Host do MySQL HeatWave (VCN privada OCI) |
| `DB_PORT` | `3306` | Porta do MySQL HeatWave |
| `DB_USER` | `principalUser` | Usuário do MySQL |
| `DB_PASSWORD` | - | Senha do MySQL HeatWave |
| `DB_NAME` | `paloma_security` | Banco de dados |
| `ADMIN_PASSWORD` | - | Senha mestra de acesso ao dashboard web |
| `INTERNAL_SECRET` | - | Token secreto para webhook de eventos do Fail2ban |
| `FAIL2BAN_SOCK` | `/var/run/fail2ban/fail2ban.sock` | Caminho do socket IPC do Fail2ban |

## 🚀 Estrutura do Projeto
```
├── Dockerfile                  # Multi-stage build (Golang Alpine -> Alpine minimal)
├── docker-compose.yml          # Configuração para orquestração Coolify
├── migrations/                 # Migrações SQL versionadas
│   └── 000001_init_schema.up.sql
├── internal/
│   ├── db/                     # Conexão com MySQL HeatWave e engine de migrações
│   ├── fail2ban/               # Cliente IPC e sanitização de IPs
│   └── api/                    # Handlers REST, webhook e middleware de autenticação
├── web/                        # Interface gráfica (HTML5, OKLCH CSS, Vanilla JS)
└── main.go                     # Ponto de entrada do serviço
```
