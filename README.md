# pass-manager

Gerenciador de senhas local pra Linux, feito em C++ com Qt6. Fiz porque tinha senha espalhada em bloco de notas e cansei de procurar.

Tudo fica num arquivo só, criptografado, na sua máquina. Não tem sincronização, conta, nem nada indo pra internet. E isso não é só promessa: o próprio processo é proibido pelo kernel de abrir conexão de rede (ver Sandbox mais abaixo).

## Como funciona

Na primeira vez você define uma senha mestra e recebe uma chave de recuperação. Anota ela no papel.

Os dados são cifrados com XChaCha20-Poly1305 usando uma chave aleatória. Essa chave fica guardada no próprio arquivo, cifrada de duas formas:

- com a senha mestra (Argon2id, parâmetros "moderate" da libsodium, uns 256 MB de memória) combinada com um segredo guardado no TPM da máquina
- com a chave de recuperação

O segredo do TPM é selado pelo `systemd-creds` (modo usuário, `tpm2+host`). Na prática, quem copiar o `vault.bin` não consegue testar senhas em outro computador, mesmo que a sua senha mestra seja fraca. Não amarrei a nenhum PCR, então atualização de BIOS não trava o cofre.

Sem TPM (ou sem `systemd-creds`), o app funciona só com a senha mestra. A barra de status mostra qual dos dois está valendo.

Qualquer alteração no arquivo faz ele recusar abrir. O cofre fica em `~/.local/share/pass-manager/vault.bin` com permissão 600, e a gravação é atômica: se cair a energia no meio de um save, o arquivo antigo continua inteiro.

Cofres do formato antigo (v1) são convertidos sozinhos na primeira vez que você abre. Nessa hora aparece a chave de recuperação.

Cada entrada tem título, categoria, usuário, senha, URL e notas. Tem busca, filtro por categoria e gerador de senhas.

### Recuperação

Na tela de desbloqueio tem "Usar chave de recuperação". Depois de entrar com ela, o app pede uma senha mestra nova e sela um segredo novo no TPM da máquina atual. É assim também que se leva o cofre pra outro computador, ou que se recupera depois de trocar placa-mãe ou limpar o TPM na BIOS.

A senha mestra dá pra trocar a qualquer momento pela barra lateral. A chave de recuperação continua a mesma.

**Perdeu a senha mestra e a chave de recuperação, perdeu o cofre.**

## Segurança

- trava sozinho depois de 5 minutos sem uso, quando a tela bloqueia, quando o sistema vai suspender e quando o logind manda bloquear a sessão
- só roda uma instância por vez (`flock` num arquivo de trava). Abrir de novo só traz a janela já aberta pra frente, via D-Bus. Antes, duas janelas abertas podiam sobrescrever o que a outra salvou
- a chave fica em memória travada (não vai pro swap) e é apagada ao bloquear
- o processo desativa core dump e ptrace (`PR_SET_DUMPABLE`)
- ao copiar senha, o clipboard recebe a marcação `x-kde-passwordManagerHint`, que alguns gerenciadores de clipboard respeitam pra não guardar no histórico

### Sandbox

Logo depois de iniciar, o processo se tranca, sem volta. Tudo o que ele abrir depois herda as mesmas restrições:

- **Landlock:** só pode criar ou escrever arquivos em `~/.local/share/pass-manager` e `~/.cache`, e só pode executar programas de `/usr` (o `systemd-creds`)
- **seccomp:** não consegue criar socket IPv4, IPv6 nem de pacote, nem usar io_uring. Socket Unix continua liberado, porque o X11 e o D-Bus precisam

O Landlock também bloqueia rede, mas nessa versão do kernel ele só cobre TCP. Por isso a rede fica com o seccomp, que corta UDP também.

O botão "Abrir" da URL pede pro xdg-desktop-portal abrir o navegador. Assim o navegador não nasce dentro do sandbox, sem internet. Só abre `http` e `https`.

Se o kernel não suportar alguma camada, o app abre do mesmo jeito e avisa no stderr.

Um detalhe: com o X11 encaminhado por SSH (`ssh -X`) a conexão com a tela já existe antes do sandbox, então funciona. Mas qualquer coisa que dependa de abrir conexão de rede nova vai falhar, de propósito.

### No sistema

Não depende do app, mas recomendo: no Debian, o `kernel.yama.ptrace_scope` vem em 0, o que deixa qualquer processo seu ler a memória de outro processo seu. O pass-manager se protege disso sozinho, o resto dos seus programas não.

```
echo 'kernel.yama.ptrace_scope = 1' | sudo tee /etc/sysctl.d/10-ptrace.conf
sudo sysctl --system
```

Com isso, só processos pai conseguem inspecionar os filhos. Debugger continua funcionando se você iniciar o programa por ele.

## Compilando

Dependências no Debian/Ubuntu:

```
sudo apt install cmake ninja-build qt6-base-dev libsodium-dev
```

Pro TPM, precisa de systemd 256 ou mais novo (`systemd-creds --user`) e de um TPM 2.0. Sem isso compila e roda igual, só sem essa camada.

Build e instalação (vai pra `~/.local`, sem sudo):

```
cmake -S . -B build -G Ninja
cmake --build build
cmake --install build
```

Depois disso aparece "Pass Manager" no menu de aplicativos. Também dá pra rodar `pass-manager` direto no terminal, se `~/.local/bin` estiver no PATH.

Testes:

```
./build/vault_test     # criptografia, TPM, recuperação, troca de senha, migração do v1
./build/sandbox_test   # Landlock e seccomp
```

O `vault_test` pula a parte do TPM se a máquina não tiver um.

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

Copie o `vault.bin` e guarde a chave de recuperação em outro lugar (papel). O arquivo sozinho não abre nem com a senha mestra fora desta máquina. Em outra máquina, ele só abre com a chave de recuperação.

## Commits assinados

Os commits deste repositório são assinados com chave SSH. Pra conferir localmente:

```
git log --show-signature
```

## Falta fazer

- renomear categoria (hoje é só editar o campo em cada entrada)
- gerar uma chave de recuperação nova sem precisar recriar o cofre
