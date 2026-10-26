# pass-manager

Gerenciador de senhas local pra Linux, feito em C++ com Qt6. Fiz porque tinha senha espalhada em bloco de notas e cansei de procurar.

Tudo fica num arquivo só, criptografado, na sua máquina. Não tem sincronização, conta, nem nada indo pra internet. O próprio kernel impede o processo de abrir conexão de rede (ver Sandbox mais abaixo, inclusive o que ele não cobre).

## Como funciona

Na primeira vez você define uma senha mestra e recebe uma chave de recuperação. Anota ela no papel.

Os dados são cifrados com XChaCha20-Poly1305 usando uma chave aleatória. Essa chave fica guardada no próprio arquivo, cifrada de duas formas:

- com a senha mestra (Argon2id, parâmetros "moderate" da libsodium, uns 256 MB de memória) combinada com um segredo guardado no TPM da máquina
- com a chave de recuperação

O segredo do TPM é selado pelo `systemd-creds` (modo usuário, `tpm2+host`). Na prática, quem copiar o `vault.bin` não consegue testar senhas em outro computador, mesmo que a sua senha mestra seja fraca. Não amarrei a nenhum PCR, então atualização de BIOS não trava o cofre.

Se a máquina não tem TPM (ou não tem `systemd-creds`), o app funciona só com a senha mestra, e a barra de status mostra qual dos dois está valendo. Se o TPM existe mas falha na hora de criar o cofre ou trocar a senha, a operação dá erro em vez de seguir sem ele.

Qualquer alteração no arquivo faz ele recusar abrir. O cofre fica em `~/.local/share/pass-manager/vault.bin` com permissão 600, e a gravação é atômica: se cair a energia no meio de um save, o arquivo antigo continua inteiro.

Cofres do formato antigo (v1) são convertidos sozinhos na primeira vez que você abre. Nessa hora aparece a chave de recuperação.

Cada entrada tem título, categoria, usuário, senha, URL e notas. Tem busca, filtro por categoria e gerador de senhas.

### Recuperação

Na tela de desbloqueio tem "Usar chave de recuperação". Depois de entrar com ela, o app pede uma senha mestra nova e sela um segredo novo no TPM da máquina atual. É assim também que se leva o cofre pra outro computador, ou que se recupera depois de trocar placa-mãe ou limpar o TPM na BIOS.

A senha mestra dá pra trocar a qualquer momento pela barra lateral, e a chave de recuperação continua a mesma. Se perder a chave (ou não tiver anotado), "Chave de recuperação" na barra lateral gera outra pedindo a senha mestra, e a antiga deixa de valer.

**Perdeu a senha mestra e a chave de recuperação, perdeu o cofre.**

### Digital

Funciona como no celular. Depois de ligar o notebook ou fazer login, a primeira abertura é pela senha mestra. A partir daí, quando o cofre travar, a tela de desbloqueio aceita a senha ou a digital, o que vier primeiro. Cinco digitais erradas seguidas e ele volta a exigir a senha.

Liga sozinho quando o `fprintd` tem um dedo seu cadastrado:

```
sudo apt install fprintd
fprintd-enroll
```

(ou em Configurações > Usuários > Login por impressão digital, no GNOME)

Como funciona por baixo: o `fprintd` só responde se a digital bateu ou não, ele não guarda chave nenhuma. Então, depois que você abre com a senha, a chave do cofre fica no keyring do kernel (`keyctl`, keyring do usuário). Ela fica na memória do kernel, nunca vai pro swap, e some no logout ou no reboot, por isso a senha volta a ser pedida.

O preço é que, nesse meio tempo, um programa rodando com o seu usuário consegue ler essa chave sem passar pela digital. É o mesmo alcance que esse programa já teria no X11 lendo o teclado enquanto você digita a senha, mas vale saber. Se isso não for aceitável, é só não cadastrar digital.

O leitor só é usado enquanto a janela do cofre está em foco na tela de desbloqueio. No resto do tempo ele fica livre pra tela de bloqueio do GNOME e outros programas.

## Segurança

- trava sozinho depois de 5 minutos sem uso, quando a tela bloqueia, quando o logind manda bloquear a sessão e antes do sistema suspender (com um inibidor `delay` do logind, então o suspend espera o cofre travar)
- ao travar, fecha qualquer diálogo aberto. A exceção é o da chave de recuperação, que só fecha depois de marcar que anotou
- só roda uma instância por vez (`flock` num arquivo de trava). Abrir de novo só traz a janela já aberta pra frente, via D-Bus. Antes, duas janelas abertas podiam sobrescrever o que a outra salvou
- a chave fica em memória travada (não vai pro swap) e é apagada ao bloquear
- o processo desativa core dump e ptrace (`PR_SET_DUMPABLE`)
- ao copiar senha, o clipboard recebe a marcação `x-kde-passwordManagerHint`, que alguns gerenciadores de clipboard respeitam pra não guardar no histórico

### Sandbox

A primeira coisa que o processo faz, antes de subir o Qt e qualquer thread, é se trancar, sem volta. Tudo o que ele abrir depois (threads e processos filhos) herda as mesmas restrições:

- **Landlock:** só pode criar ou escrever arquivos em `~/.local/share/pass-manager` e `~/.cache`, e só pode executar programas de `/usr` (o `systemd-creds`)
- **seccomp:** só cria socket Unix (X11 e D-Bus) e netlink (que fala só com o kernel). Qualquer outra família é recusada. Também bloqueia io_uring, `ptrace`, `process_vm_readv/writev` e `pidfd_getfd`, que serviriam pra pegar memória ou socket emprestado de outro processo seu

O Landlock também sabe bloquear rede, mas nessa versão do kernel ele só cobre TCP. Por isso a rede fica com o seccomp, numa lista do que é permitido, e não do que é proibido: famílias como AF_SMC caem pra TCP comum e passariam por uma lista de bloqueio.

O botão "Abrir" da URL pede pro xdg-desktop-portal abrir o navegador. Assim o navegador não nasce dentro do sandbox, sem internet. Só abre `http` e `https`.

Se o kernel não suportar alguma camada, o app abre do mesmo jeito e avisa no stderr.

**O que o sandbox não cobre.** Ele segura biblioteca bugada ou mal-comportada, não um processo totalmente comprometido. O socket Unix do D-Bus continua aberto, e por ele dá pra pedir pro systemd do usuário rodar um programa fora do sandbox. No X11 qualquer janela consegue ler o teclado de outra. Fechar isso de verdade exigiria filtrar o D-Bus (`xdg-dbus-proxy`) e rodar em Wayland.

X11 encaminhado por SSH (`ssh -X`) não funciona: a conexão com a tela é TCP e só é aberta depois do sandbox.

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

O `vault_test` pula a parte do TPM se a máquina não tiver um. A digital não tem teste automático: precisa de dedo no leitor.

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
