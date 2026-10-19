# pass-manager

Gerenciador de senhas local pra Linux, feito em C++ com Qt6. Fiz porque tinha senha espalhada em bloco de notas e cansei de procurar.

Tudo fica num arquivo só, criptografado, na sua máquina. Não tem sincronização, conta, nem nada indo pra internet.

## Como funciona

Na primeira vez você define uma senha mestra. A chave é derivada dela com Argon2id (libsodium, parâmetros "moderate", uns 256 MB de memória) e o cofre é cifrado com XChaCha20-Poly1305. Qualquer alteração no arquivo faz ele recusar abrir.

O cofre fica em `~/.local/share/pass-manager/vault.bin` com permissão 600. A gravação é atômica, então se cair a energia no meio de um save o arquivo antigo continua inteiro.

Alguns detalhes:

- trava sozinho depois de 5 minutos sem uso e quando a tela do GNOME bloqueia
- a chave fica em memória travada (não vai pro swap) e é apagada ao bloquear
- o processo desativa core dump e ptrace (`PR_SET_DUMPABLE`)
- ao copiar senha, o clipboard recebe a marcação `x-kde-passwordManagerHint`, que alguns gerenciadores de clipboard respeitam pra não guardar no histórico

Cada entrada tem título, categoria, usuário, senha, URL e notas. Tem busca, filtro por categoria e gerador de senhas.

**Não existe recuperação da senha mestra.** Esqueceu, perdeu.

## Compilando

Dependências no Debian/Ubuntu:

```
sudo apt install cmake ninja-build qt6-base-dev libsodium-dev
```

Build e instalação (vai pra `~/.local`, sem sudo):

```
cmake -S . -B build -G Ninja
cmake --build build
cmake --install build
```

Depois disso aparece "Pass Manager" no menu de aplicativos. Também dá pra rodar `pass-manager` direto no terminal, se `~/.local/bin` estiver no PATH.

Pra rodar o teste da parte de criptografia:

```
./build/vault_test
```

## Atalhos

| Atalho | Ação |
|---|---|
| Ctrl+N | nova entrada |
| Ctrl+F | buscar |
| Ctrl+B | copiar usuário |
| Ctrl+Shift+C | copiar senha |
| Ctrl+L | bloquear |

As alterações salvam sozinhas.

## Backup

Basta copiar o `vault.bin`. Sem a senha mestra ele não serve pra nada, então pode guardar em pendrive ou nuvem tranquilo.

## Falta fazer

- trocar a senha mestra
- renomear categoria (hoje é só editar o campo em cada entrada)
