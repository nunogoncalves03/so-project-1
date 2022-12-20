# Técnico File System

O TecnicoFS (Técnico _File System_) é um sistema de ficheiros simplificado em modo utilizador.
É implementado como uma biblioteca, que pode ser usada por qualquer processo cliente que pretenda ter uma instância privada de um sistema de ficheiros no qual pode manter os seus dados.

## Interface de programação

O TecnicoFS oferece uma interface de programação (API) inspirada na API de sistema de ficheiros POSIX.
No entanto, para simplificar o projeto, a API do TecnicoFS oferece apenas um subconjunto de funções com interface simplificada:


- `int tfs_init(tfs_params const *params);`
- `int tfs_destroy();`
- `int tfs_open(char const *name, int flags);`
- `int tfs_close(int fhandle);`
- `ssize_t tfs_write(int fhandle, void const *buffer, size_t len);`
- `ssize_t tfs_read(int fhandle, void *buffer, size_t len);`
- `int tfs_copy_from_external_fs(char const *source_path, char const *dest_path);`
- `int tfs_link(char const *target_file, char const *source_file);`

- `int tfs_sym_link(char const *target_file, char const *source_file);`
- `int tfs_unlink(char const *target);`

(Nota: o tipo de dados `ssize_t` é definido no _standard_ POSIX para representar tamanhos em _bytes_, podendo também ter o valor `-1` para representar erro.
É, por exemplo, o tipo do retorno das funções `read` e `write` da API de sistema de ficheiros POSIX.)

## Estado do sistema de ficheiros

Tal como em FS tradicionais modernos, o conteúdo do FS encontra-se referenciado numa estrutura de dados principal chamada tabela de _i-nodes_, global ao FS.
Cada _i-node_ representa uma diretoria ou um ficheiro no TecnicoFS, que tem um identificador único chamado _i-number_.
O _i-number_ de uma diretoria/ficheiro corresponde ao índice do _i-node_ correspondente na tabela de _i-nodes_.
O _i-node_ consiste numa estrutura de dados que descreve os atributos da diretoria/ficheiro (aquilo que normalmente se chamam os seus _metadados_) e que referencia o conteúdo da diretoria/ficheiro (ou seja, os _dados_).

Além da tabela de _i-nodes_, existe uma região de dados, organizada em blocos de tamanho fixo.
Esta região mantém os dados de todos os ficheiros do FS, sendo esses dados referenciados a partir do _i-node_ de cada ficheiro (na tabela de _i-nodes_).
No caso de ficheiros normais, é na região de dados que é mantido o conteúdo do ficheiro (por exemplo, a sequência de caracteres que compõem um ficheiro de texto).
No caso de diretorias, a região de dados mantém a respetiva tabela, que representa o conjunto de ficheiros (ficheiros normais e subdiretorias) que existem nessa diretoria.

Para facilitar a alocação e libertação de _i-nodes_ e blocos, existe um vetor de alocação associado à tabela de _i-nodes_ e à região de dados, respetivamente.

Além das estruturas de dados mencionadas acima, que mantêm o estado durável do sistema de ficheiros, o TecnicoFS mantém uma tabela de ficheiros abertos.
Essencialmente, esta tabela conhece os ficheiros atualmente abertos pelo processo cliente do TecnicoFS e, para cada ficheiro aberto, indica onde está o cursor atual.
A tabela de ficheiros abertos é descartada quando o sistema é desligado ou termina abruptamente (ou seja, não é durável).

## Simplificações

Além de uma API simplificada, o desenho e implementação do TecnicoFS adotam algumas simplificações fundamentais, que sumarizamos de seguida:

- Em vez de uma árvore de diretorias, o TecnicoFS tem apenas uma diretoria (a raiz "/"), dentro da qual podem existir ficheiros (e.g., "/f1", "/f2", etc.) mas não outras subdiretorias.
O texto entre aspas nos exemplos anteriores é chamado o **caminho de acesso** ao ficheiro.
- O conteúdo dos ficheiros e da diretoria raiz é limitado a um bloco (cuja dimensão é determinada em tempo de compilação e que é configurada para 1KB, por omissão).
Como consequência, o _i-node_ respetivo tem um campo simples que indica qual o índice desse bloco.
- Assume-se que existe um único processo cliente, que é o único que pode aceder ao sistema de ficheiros.
Consequentemente, existe apenas uma tabela de ficheiros abertos e não há permissões nem controlo de acesso.
- A implementação das funções assume que estas são chamadas por um cliente sequencial, ou seja, a implementação pode resultar em erros caso uma ou mais funções sejam chamadas concorrentemente por duas ou mais tarefas (_threads_) do processo cliente.
Por outras palavras, não é _thread-safe_.
- As estruturas de dados que, em teoria, deveriam ser duráveis, não são mantidas em memória secundária.
Quando o TecnicoFS é terminado, o conteúdo destas estruturas de dados é perdido.