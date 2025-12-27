# Guia: Como Obter o UUID da Máquina no RustDesk

## Visão Geral

O RustDesk utiliza um identificador único por dispositivo (UUID) que é usado para validação de fingerprint e autorização de máquinas. Este guia explica como o sistema funciona e como você pode obter o UUID da sua máquina.

## Como o RustDesk Gera o UUID

O RustDesk usa diferentes estratégias para gerar o UUID dependendo da plataforma:

### Desktop (Windows, macOS, Linux)

Para plataformas desktop, o RustDesk usa a biblioteca [`machine-uid`](https://github.com/rustdesk-org/machine-uid) que:

1. **Linux**: Lê `/var/lib/dbus/machine-id` ou `/etc/machine-id`
2. **macOS**: Usa `IOPlatformUUID` via `IOKit`
3. **Windows**: Lê a chave de registro `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid`

**Código fonte** ([libs/hbb_common/src/lib.rs:310-316](../libs/hbb_common/src/lib.rs#L310-L316)):
```rust
pub fn get_uuid() -> Vec<u8> {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    if let Ok(id) = machine_uid::get() {
        return id.into();
    }
    Config::get_key_pair().1  // Fallback para chave pública
}
```

### Mobile (Android, iOS)

Em plataformas móveis, o RustDesk usa a **chave pública** do par de chaves RSA gerado pelo aplicativo como UUID. Esta chave é persistida e única por instalação.

## Como Obter o UUID da Sua Máquina

### Método 1: Via Interface do RustDesk

O RustDesk expõe o UUID através da função `get_uuid()` em [src/ui_interface.rs:777-779](../src/ui_interface.rs#L777-L779):

```rust
pub fn get_uuid() -> String {
    crate::encode64(hbb_common::get_uuid())
}
```

**Importante**: O UUID retornado é **codificado em Base64**.

### Método 2: Manualmente por Plataforma

#### Linux

```bash
# Opção 1: Machine ID (usado pelo RustDesk)
cat /var/lib/dbus/machine-id

# Opção 2: Alternativa
cat /etc/machine-id

# Converter para Base64 (mesmo formato do RustDesk)
cat /var/lib/dbus/machine-id | base64
```

#### macOS

```bash
# Obter UUID da plataforma
ioreg -d2 -c IOPlatformExpertDevice | grep IOPlatformUUID

# Converter para Base64
ioreg -d2 -c IOPlatformExpertDevice | grep IOPlatformUUID | awk '{print $3}' | tr -d '"' | base64
```

#### Windows

```powershell
# Via PowerShell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid | Select-Object -ExpandProperty MachineGuid

# Converter para Base64 (PowerShell)
$uuid = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid | Select-Object -ExpandProperty MachineGuid
[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($uuid))
```

### Método 3: Programaticamente (Rust)

Se você está desenvolvendo em Rust, pode usar o mesmo código do RustDesk:

```rust
use base64::{Engine as _, engine::general_purpose};

fn get_machine_uuid() -> String {
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        if let Ok(id) = machine_uid::get() {
            return general_purpose::STANDARD.encode(id.as_bytes());
        }
    }

    // Fallback: usar chave pública
    // (requer implementação de Config::get_key_pair())
    String::from("fallback")
}
```

**Dependência necessária** (Cargo.toml):
```toml
[dependencies]
machine-uid = { git = "https://github.com/rustdesk-org/machine-uid" }
base64 = "0.22"
```

## Como o UUID é Usado na Validação de Fingerprint

O sistema de validação funciona assim:

1. **Obtenção do UUID bruto**: `hbb_common::get_uuid()` retorna `Vec<u8>`
2. **Codificação Base64**: `crate::encode64()` converte para string Base64
3. **Envio para API**: JSON com `{"machine_id": "<uuid_base64>"}`
4. **Validação**: API verifica se o UUID está autorizado

**Código de validação** ([src/common.rs:1382-1399](../src/common.rs#L1382-L1399)):
```rust
pub async fn validate_machine_fingerprint() -> Result<(), String> {
    log::info!("Starting machine fingerprint validation");

    // Passo 1: Obter UUID bruto
    let uuid_bytes = hbb_common::get_uuid();

    // Passo 2: Codificar em Base64
    let machine_id = crate::encode64(uuid_bytes);

    // Passo 3: Verificar se não está vazio
    if machine_id.is_empty() {
        return Err("UUID da máquina não disponível.".to_string());
    }

    log::debug!("Machine ID (base64): {}", machine_id);

    // Passo 4: Enviar para API
    let payload = serde_json::json!({
        "machine_id": machine_id
    });

    // ... resto da validação HTTP
}
```

## Exemplo Prático

Para registrar o UUID da sua máquina na API de validação:

```bash
# 1. Obter o UUID (Linux)
UUID=$(cat /var/lib/dbus/machine-id)

# 2. Converter para Base64
UUID_BASE64=$(echo -n "$UUID" | base64)

# 3. Registrar na API
curl -X POST https://webhook.ghms.net.br/webhook/rustdesk/signin \
  -H "Content-Type: application/json" \
  -d "{\"machine_id\": \"$UUID_BASE64\"}"
```

## Observações Importantes

1. **Persistência**: O UUID do RustDesk **não muda** após instalação (exceto reinstalação completa)
2. **Formato**: Sempre use **Base64** ao enviar para a API
3. **Plataforma**: Desktop usa `machine-uid`, Mobile usa chave pública RSA
4. **Fallback**: Se `machine-uid::get()` falhar, usa a chave pública do par de chaves
5. **Segurança**: O UUID é enviado via HTTPS, não requer criptografia adicional

## Referências

- Implementação do UUID: [libs/hbb_common/src/lib.rs](../libs/hbb_common/src/lib.rs)
- Validação de fingerprint: [src/common.rs](../src/common.rs)
- Interface UI: [src/ui_interface.rs](../src/ui_interface.rs)
- Biblioteca machine-uid: https://github.com/rustdesk-org/machine-uid