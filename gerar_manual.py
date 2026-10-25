"""Gera o Manual de Uso da Loja de Envios em PDF (ReportLab).

Uso: python gerar_manual.py  ->  Manual_de_Uso_Loja_de_Envios_v1.1.pdf
Edite o conteudo abaixo e rode de novo para publicar uma nova versao.
"""
import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

VERSAO = "1.1"
DATA = "Outubro de 2026"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAIDA = os.path.join(BASE_DIR, f"Manual_de_Uso_Loja_de_Envios_v{VERSAO}.pdf")
LOGO = os.path.join(BASE_DIR, "static", "img", "logo-loja-de-envios.jpg")

LARANJA = colors.HexColor("#F07A1A")
ESCURO = colors.HexColor("#1B2333")
CINZA = colors.HexColor("#5F6B7A")
LINHA = colors.HexColor("#D9DEE5")
FUNDO = colors.HexColor("#F3F5F8")
FUNDO_DESTAQUE = colors.HexColor("#FFF6EE")

H1 = ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=ESCURO, spaceBefore=6, spaceAfter=10)
H2 = ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=13.5, leading=17, textColor=LARANJA, spaceBefore=10, spaceAfter=5)
TXT = ParagraphStyle("txt", fontName="Helvetica", fontSize=10, leading=14, textColor=ESCURO)
TXT_CEL = ParagraphStyle("cel", parent=TXT, fontSize=9, leading=12)
TXT_CEL_B = ParagraphStyle("celb", parent=TXT_CEL, fontName="Helvetica-Bold")
NUM = ParagraphStyle("num", parent=TXT, fontName="Helvetica-Bold", textColor=LARANJA, fontSize=11)
BOX_T = ParagraphStyle("boxt", parent=TXT, fontName="Helvetica-Bold", fontSize=9, leading=12)
BOX = ParagraphStyle("box", parent=TXT, fontSize=9, leading=12)
CAPA_T = ParagraphStyle("capat", parent=H1, fontSize=24, leading=28, alignment=TA_CENTER)
CAPA = ParagraphStyle("capa", parent=TXT, textColor=CINZA, alignment=TA_CENTER, leading=18)
LARGURA = A4[0] - 4 * cm


def passos(*itens):
    linhas = [[Paragraph(str(i), NUM), Paragraph(t, TXT)] for i, t in enumerate(itens, 1)]
    t = Table(linhas, colWidths=[0.7 * cm, LARGURA - 0.7 * cm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                           ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t


def topicos(*itens):
    linhas = [[Paragraph('<font color="#F07A1A">&#9679;</font>', TXT), Paragraph(t, TXT)] for t in itens]
    t = Table(linhas, colWidths=[0.6 * cm, LARGURA - 0.6 * cm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0),
                           ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t


def destaque(titulo, texto):
    t = Table([[[Paragraph(titulo, BOX_T), Paragraph(texto, BOX)]]], colWidths=[LARGURA])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), FUNDO_DESTAQUE), ("BOX", (0, 0), (-1, -1), 0.6, LARANJA),
                           ("LINEBEFORE", (0, 0), (0, -1), 3, LARANJA), ("LEFTPADDING", (0, 0), (-1, -1), 10),
                           ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
    return KeepTogether([Spacer(1, 6), t, Spacer(1, 6)])


def tabela(cabecalho, linhas, larguras):
    dados = [[Paragraph(c, TXT_CEL_B) for c in cabecalho]] + [[Paragraph(c, TXT_CEL) for c in l] for l in linhas]
    t = Table(dados, colWidths=[LARGURA * f for f in larguras], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), FUNDO), ("GRID", (0, 0), (-1, -1), 0.5, LINHA),
                           ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 5),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 5), ("LEFTPADDING", (0, 0), (-1, -1), 6)]))
    return t


def conteudo():
    c = []
    # Capa
    c += [Spacer(1, 3 * cm), Image(LOGO, 3.2 * cm, 3.2 * cm), Spacer(1, 0.6 * cm),
          Paragraph("Manual de Uso", CAPA_T), Paragraph("Loja de Envios - Sistema de Balcão", CAPA),
          Paragraph(f"Versão {VERSAO} | {DATA}", CAPA), Spacer(1, 1.2 * cm),
          destaque("Objetivo", "Orientar Master, Administrador, Operador de Balcão e Expedidor nas atividades diárias do sistema."),
          Spacer(1, 0.4 * cm),
          Paragraph("Esta versão atualiza os perfis de acesso: o antigo Operador de Caixa passa a se chamar Operador de "
                    "Balcão, com telas próprias, e cada usuário pode alterar o próprio nome e login. A disponibilidade de "
                    "serviços externos depende de credenciais válidas, contrato e homologação de cada integração.", CAPA),
          PageBreak()]

    c += [Paragraph("1. Primeiros passos", H1), Paragraph("1.1 Abrir o sistema", H2),
          passos("No Windows, abra a pasta do sistema e execute <b>iniciar_sistema.bat</b>.",
                 "Aguarde a verificação dos componentes. Na primeira abertura, essa etapa pode demorar alguns minutos.",
                 "O navegador abrirá o endereço local <b>127.0.0.1:5000</b>.",
                 "Informe seu usuário e senha. Cada usuário pode permanecer conectado em apenas uma máquina por vez."),
          destaque("Segurança", "Não compartilhe sua senha. Um novo acesso com o mesmo usuário encerra a sessão anterior."),
          Paragraph("1.2 Perfis e permissões", H2),
          tabela(["Perfil", "Acesso principal"], [
              ["Master", "Todas as telas, incluindo Integrações, SLA, Painel Master, licenças e administração geral."],
              ["Administrador", "Todas as rotinas da loja: envio, clientes, estoque, relatórios, exportação, usuários, "
                                "tarifas à vista, Livro Caixa, conferência de faturas, cobrança, log e configurações."],
              ["Operador de Balcão", "Envio, Histórico, Enviados, Controle de estoque (somente o próprio caixa), "
                                     "Consultar Reversa, Recepção de Objetos, Tarifas à vista e Livro Caixa "
                                     "(somente os próprios lançamentos)."],
              ["Expedidor", "Expedição, triagem, romaneio de expedição e exportação."],
          ], [0.28, 0.72]),
          Spacer(1, 4),
          Paragraph("Telas fora do perfil não aparecem no menu e, se abertas pelo endereço, mostram acesso negado. "
                    "Usuários cadastrados como Operador de Caixa foram convertidos automaticamente para Operador de Balcão.", TXT),
          Paragraph("1.3 Padrões de preenchimento", H2),
          topicos("Datas aparecem em <b>dd/mm/aaaa</b>.", "Valores aparecem em Real: <b>R$ 1.234,56</b>.",
                  "CPF, CNPJ e CEP são formatados e validados automaticamente.",
                  "Informe primeiro o CEP. O sistema completa logradouro, bairro, cidade e UF; informe número e, se houver, complemento.",
                  "Se o número ficar vazio, o sistema utiliza <b>S/N</b>."),
          Paragraph("1.4 Meu usuário e senha", H2),
          passos("No topo da tela, clique em <b>Meu usuário</b>.",
                 "Altere o nome e o nome de usuário (login). Logins de loja usam o domínio <b>@lojadeenvios</b>.",
                 "Confirme com a senha atual e clique em <b>Salvar</b>. O próximo acesso já usa o novo login.",
                 "Para mudar a senha, use <b>Trocar senha</b>, no topo da tela."),
          PageBreak()]

    c += [Paragraph("2. Nova cotação", H1), Paragraph("2.1 Identificação das partes", H2),
          passos("Comece pelo <b>CPF/CNPJ do remetente</b>. Se houver cadastro, selecione a sugestão apresentada.",
                 "Confirme nome, CEP, endereço e número do remetente.",
                 "Repita o processo para o <b>CPF/CNPJ do destinatário</b>.",
                 "Corrija imediatamente qualquer aviso de CPF, CNPJ ou CEP inválido. Os demais campos permanecem preenchidos."),
          Paragraph("2.2 Pacote e documento", H2),
          topicos("Informe peso e, quando solicitado, comprimento, largura e altura.",
                  "Para envelope elegível, marque a opção correspondente para dispensar dimensões.",
                  "Escolha Declaração de Conteúdo, NF-e, NFC-e ou Cupom Fiscal.",
                  "NF-e, NFC-e e Cupom Fiscal usam chave de acesso de 44 dígitos.",
                  "Na Declaração de Conteúdo, cadastre conteúdo, quantidade e valor de todos os itens.",
                  "Ao indicar bateria, o adicional 095 é aplicado automaticamente.",
                  "Selecione os serviços adicionais disponíveis. O seguro é cobrado pela tabela à vista."),
          Paragraph("2.3 Comparar e aceitar", H2),
          passos("Depois de preencher remetente, destinatário e peso, consulte as opções de envio.",
                 "Os Correios aparecem primeiro. Cada opção mostra transportadora, serviço, frete, adicionais, prazo e total.",
                 "Escolha a alternativa aceita pelo cliente e confirme o meio de pagamento.",
                 "Para cliente autorizado, o meio Faturado respeita o limite de crédito cadastrado.",
                 "Confirme a geração da postagem e do recibo."),
          destaque("Atenção", "Integrações ainda não homologadas podem exibir estimativas identificadas. Não trate "
                              "estimativa como resposta oficial da transportadora."),
          Paragraph("2.4 Carga fracionada e consolidada", H2),
          topicos("Use Carga fracionada para uma cotação individual de carga.",
                  "Use Carga consolidada para demandas recebidas dos integradores de carga ou do futuro Portal Cliente."),
          PageBreak()]

    c += [Paragraph("3. Etiquetas, recibos e reimpressão", H1), Paragraph("3.1 Etiqueta oficial", H2),
          topicos("A etiqueta de PAC ou SEDEX é obtida da PPN dos Correios.",
                  "Declaração de Conteúdo gera o rótulo oficial e uma segunda página 10 x 15 cm com a DACE.",
                  "NF-e, NFC-e e Cupom Fiscal utilizam a chave de acesso e não geram a segunda etiqueta DACE.",
                  "Depois que a PPN é criada, os dados do envio não podem ser alterados.",
                  "O canto inferior da etiqueta informa classe PO/GO, posição e direção do plano de triagem."),
          Paragraph("3.2 Impressão", H2),
          tabela(["Documento", "Impressora sugerida", "Formato"], [
              ["Etiqueta", "Zebra", "10 x 15 cm"], ["Recibo", "Bematech ou impressora definida", "Térmico / configurado"],
              ["Romaneio", "Impressora A4", "A4"], ["Relatórios", "Impressora A4", "A4 ou PDF"]], [0.3, 0.4, 0.3]),
          Spacer(1, 4),
          Paragraph("As impressoras são escolhidas entre as disponíveis no Windows. A preferência fica salva até que um "
                    "administrador a altere.", TXT),
          Paragraph("3.3 Reimprimir", H2),
          passos("Na tela de nova cotação ou na lista de enviados, clique em <b>Reimprimir</b>.",
                 "Escolha Zebra para a etiqueta oficial ou PDF para impressora local.",
                 "Como atalho, pressione <b>F6</b>, selecione a data e escolha uma etiqueta emitida."),
          destaque("Visibilidade no F6", "Operadores de Balcão veem apenas as próprias etiquetas. Master e Administrador "
                                         "veem todos os envios e o operador responsável."),
          Paragraph("3.4 Recibo faturado", H2),
          Paragraph("O pagamento faturado gera duas vias: uma via normal para o cliente e outra via com campos para "
                    "assinatura e RG.", TXT),
          Paragraph("3.5 Conteúdo dos recibos", H2),
          tabela(["Recibo", "O que traz"], [
              ["Postagem", "Dados da encomenda (serviço, objeto, preço e adicionais), com tipo, dimensões "
                           "(C x L x A) e peso logo abaixo; depois os produtos vendidos, remetente, destinatário e total."],
              ["Recepção de Objetos", "Dados da encomenda (serviço, PPN, status, documento e adicionais) com as dimensões e o "
                                      "peso conferidos no balcão, remetente e destinatário com endereço completo, valor e pagamento."],
              ["Logística reversa", "Autorização, data limite e, para cada objeto, os dados da encomenda com as medidas conferidas "
                                    "no balcão, remetente e destinatário. Apenas comprovante: nada é postado."],
          ], [0.26, 0.74]),
          PageBreak()]

    c += [Paragraph("4. Clientes, enviados, estoque e caixa", H1), Paragraph("4.1 Clientes", H2),
          topicos("O remetente é salvo como cliente sem duplicação de CPF/CNPJ.",
                  "Ao digitar o nome ou documento na cotação, o sistema sugere cadastros existentes.",
                  "A tela <b>Clientes</b> é exclusiva de Administrador e Master, inclusive Adicionar Novo Cliente.",
                  "No cadastro, o administrador pode liberar faturamento e definir o limite máximo de crédito.",
                  "Abaixo do cliente ficam os envios anteriores para consulta e recorrência."),
          Paragraph("4.2 Enviados e Histórico", H2),
          topicos("Enviados apresenta remetente, destinatário, endereço e dados completos do objeto.",
                  "Histórico registra as cotações e operações realizadas.",
                  "O Operador de Balcão visualiza apenas seus registros; Master e Administrador visualizam toda a loja."),
          Paragraph("4.3 Controle de estoque", H2),
          passos("O Administrador cadastra os produtos e registra as entradas no estoque geral da loja.",
                 "Somente o Administrador abastece o operador: use <b>Repassar ao operador de balcão</b> ou atenda os "
                 "<b>Pedidos de suprimento</b>.",
                 "O Operador de Balcão vê apenas o próprio estoque no caixa e, quando precisar, usa <b>Pedir suprimento "
                 "ao Administrador</b>. Ele não vê o saldo da loja nem o estoque de outros operadores.",
                 "O operador confere o estoque ao abrir e ao fechar o caixa.",
                 "Na cotação, selecione apenas produtos disponíveis no estoque do operador.",
                 "Os produtos vendidos aparecem separadamente no recibo e ficam preparados para integração com o Fluxo de Caixa."),
          Paragraph("4.4 Livro Caixa", H2),
          topicos("Depois do fechamento e da conferência do estoque, o Administrador registra a sangria, que entra no Livro Caixa.",
                  "O Operador de Balcão consulta somente os próprios lançamentos; Master e Administrador veem todos."),
          PageBreak()]

    c += [Paragraph("5. Expedição, triagem e romaneio", H1), Paragraph("5.1 Expedir por código de barras", H2),
          passos("Abra Expedição e mantenha o cursor no campo de leitura.", "Leia o código de barras de cada objeto.",
                 "Confira a confirmação do sistema antes de ler o próximo pacote.",
                 "Ao finalizar, gere um romaneio para cada transportadora correspondente."),
          Paragraph("5.2 Triagem", H2),
          topicos("A tabela de triagem utiliza CEP, posição e tamanho.",
                  "Classificação GO: qualquer lado acima de 41 cm; dois lados acima de 36 cm; ou peso físico acima de 10 kg.",
                  "Abaixo desses critérios, a classificação é PO.",
                  "Quando não houver tamanho cadastrado, o sistema usa somente a posição."),
          Paragraph("5.3 Romaneio", H2),
          topicos("Cada romaneio contém apenas objetos da mesma transportadora.", "O documento é preparado para impressão A4.",
                  "O Expedidor, Administrador e Master podem consultar o Relatório de Expedição."),
          destaque("Conferência", "Não entregue objetos sem leitura confirmada. Antes de imprimir, confira transportadora, "
                                  "quantidade e códigos do romaneio."),
          PageBreak()]

    c += [Paragraph("6. Consultar Reversa e receber objetos", H1), Paragraph("6.1 Consultar Reversa", H2),
          passos("Abra Consultar Reversa.", "Digite ou leia o código da autorização.", "Clique em Consultar.",
                 "Quando estiver correta, a tela mostra somente a data-limite operacional. Nenhum atendimento ou postagem é iniciado."),
          topicos("A loja utiliza uma data-limite operacional de um dia antes da validade oficial.",
                  "Quando a consulta não puder continuar, a tela informa: Objeto Vencido, Postado ou Erro de Regras.",
                  "A tela mostra a data-limite da loja e, abaixo, a validade informada pelos Correios.",
                  "Em <b>Conferir medidas</b>, digite peso real e dimensões do volume: o sistema compara o peso tarifado "
                  "com o da autorização e com os limites dos Correios e avisa se haverá erro de negócio. É só "
                  "conferência; nada é postado.",
                  "Use <b>Gerar recibo</b> para entregar ao cliente o comprovante com os dados da autorização. "
                  "O recibo não posta o objeto."),
          Paragraph("6.2 Recepção de Objetos", H2),
          passos("Informe a etiqueta e o CEP do destinatário e clique em Verificar etiqueta e CEP na PPN.",
                 "O sistema confere os dois dados e consulta em modo somente leitura o módulo A Faturar do Correios Atende, "
                 "mostrando no frontend somente os dados cadastrados na PPN.",
                 "A validação confere objeto, status, remetente, destinatário, endereços, serviço, peso, dimensões, documento e adicionais.",
                 "Se faltar um dado obrigatório, o recebimento fica bloqueado. Com os dados completos, confirme e registre o recebimento.",
                 "Ao ser aceito, o objeto entra automaticamente e sem duplicação na fila de Expedição da transportadora correspondente.",
                 "Emita o comprovante para o cliente. Se as medidas foram conferidas, o recibo sai com o peso e as dimensões "
                 "conferidos no balcão; as medidas da criação ficam guardadas no banco para comparação. "
                 "O preço do serviço é definido pelo Administrador em Configurações."),
          topicos("Antes de receber, use <b>Conferir medidas</b> com o peso real e as dimensões do volume para saber se "
                  "o peso tarifado estoura o da PPN. É só conferência: nada é recebido nem postado.",
                  "Na Reversa e na Recepção, o sistema guarda as medidas da criação e cada conferência no banco, para comparação."),
          destaque("Limite das consultas", "A Reversa e a Recepção apenas consultam dados. O portal externo não é mostrado "
                                           "e nenhuma etapa posterior é executada."),
          PageBreak()]

    c += [Paragraph("7. Administração", H1), Paragraph("7.1 Integrações", H2),
          topicos("A tela Integrações é exclusiva do Master.",
                  "As integrações são agrupadas em Meios de Pagamento, Transportadoras, Integradores de Frete, Marketplaces e ERPs.",
                  "Use Testar e Salvar em cada integração configurada.",
                  "Correios: preserve usuário, código de acesso, cartão, contrato e demais dados já validados.",
                  "O nível do contrato é consultado ao salvar e testar a autenticação."),
          Paragraph("7.2 SLA", H2),
          Paragraph("Cada transportadora possui consulta de SLA para o Master. Use disponibilidade, tempo de resposta e "
                    "falhas observadas como apoio para decidir se a integração deve permanecer habilitada.", TXT),
          Paragraph("7.3 Tarifas à vista", H2),
          topicos("A tabela operacional reúne PAC 04510 e SEDEX 04014.",
                  "Operador de Balcão, Administrador e Master consultam a tabela, o enquadramento das cidades e o preço por CEP.",
                  "Em caso de divergência, registre a fonte e confira origem, destino, faixa de peso e quilograma adicional."),
          Paragraph("7.4 Usuários e logs", H2),
          topicos("O Administrador cadastra Operadores de Balcão e Expedidores da própria loja; o Master cadastra também Administradores.",
                  "O cadastro de novo usuário fica no topo da tela; abaixo, a lista permite alterar nome, login e perfil, "
                  "redefinir a senha e desativar ou reativar o usuário.",
                  "Cadastre cada operador com nome próprio para identificação nos logs e relatórios.",
                  "Não é permitido criar outro usuário Master.",
                  "Use o Log para auditar consultas, erros e operações importantes."),
          PageBreak()]

    c += [Paragraph("8. Relatórios, cobrança e exportação", H1),
          Paragraph("Relatórios, Cobrança, Conferência de faturas e Exportação não aparecem para o Operador de Balcão.", TXT),
          Paragraph("8.1 Relatórios", H2),
          topicos("Vendas por operador, com data inicial e final.", "Relatório por cliente, com período.",
                  "Relatório diário, selecionando um único dia e somando todos os operadores autorizados.",
                  "Curva ABC de operadores e de clientes.", "Relatório de expedição em formato de romaneio."),
          Paragraph("8.2 Cobrança", H2),
          topicos("Emissão de Fatura em lote: rotina quinzenal para clientes faturados.",
                  "Emissão de Boletos em lote: gera boletos com base nas faturas emitidas.",
                  "Gerar cobrança: utiliza a mensagem e as credenciais de e-mail configuradas para a loja.",
                  "O relatório de cobrança mostra somente pendências em aberto.",
                  "Dois dias depois do vencimento sem pagamento, o faturado é desativado automaticamente; a reabilitação "
                  "depende do Administrador."),
          Paragraph("8.3 Conferência de faturas", H2),
          Paragraph("Master e Administrador importam a fatura da integração, informam o período e conferem divergências "
                    "entre os valores cobrados e os registros do sistema.", TXT),
          Paragraph("8.4 Exportação", H2),
          Paragraph("Disponível para Master, Administrador e Expedidor. Escolha o período e gere o arquivo separado por "
                    "transportadora. Confira o conteúdo antes de enviar a terceiros.", TXT),
          PageBreak()]

    c += [Paragraph("9. Boas práticas e solução de problemas", H1), Paragraph("9.1 Antes de atualizar", H2),
          passos("Feche o sistema em todas as máquinas.",
                 "Copie o arquivo <b>envios.db</b> para uma pasta de backup identificada com a data.",
                 "Guarde também a pasta data e os arquivos de configuração da loja.",
                 "Instale ou substitua os arquivos da aplicação sem apagar o banco existente.",
                 "Abra a nova versão e confira usuários, integrações, clientes e últimos envios."),
          Paragraph("9.2 Quando ocorrer erro", H2),
          tabela(["Situação", "Ação recomendada"], [
              ["CPF/CNPJ ou CEP inválido", "Corrija somente o campo indicado; os demais dados devem permanecer."],
              ["Preço/prazo indisponível", "Teste a integração e confirme credenciais, contrato e internet."],
              ["Rótulo PPN pendente", "Use recuperar rótulo; não crie uma segunda pré-postagem."],
              ["Impressora não aparece", "Confirme se está instalada no Windows e selecione novamente em Configurações."],
              ["Sessão encerrada", "Verifique se o mesmo usuário entrou em outra máquina e faça novo login."],
              ["Acesso negado em uma tela", "A tela não pertence ao seu perfil. Peça ao Administrador, se necessário."],
              ["Objeto Vencido, Postado ou Erro de Regras", "Confira o código e a validade; nenhuma operação externa foi realizada."],
          ], [0.38, 0.62]),
          Paragraph("9.3 Checklist diário", H2),
          topicos("Abrir o caixa e conferir o estoque do operador.", "Testar a integração principal quando houver instabilidade.",
                  "Conferir etiquetas antes da entrega ao cliente.", "Ler todos os objetos na expedição.",
                  "Imprimir e conferir romaneios por transportadora.",
                  "Fechar o caixa, conferir o estoque e manter backup regular."),
          destaque("Suporte", "Ao relatar um erro, informe data, horário, usuário, tela, código do objeto e mensagem exibida. "
                              "Nunca envie senhas em capturas de tela.")]
    return c


def moldura(canvas, doc):
    canvas.saveState()
    largura, altura = A4
    if doc.page > 1:
        canvas.setFont("Helvetica-Bold", 8.5); canvas.setFillColor(ESCURO)
        canvas.drawString(2 * cm, altura - 1.4 * cm, "LOJA DE ENVIOS - MANUAL DE USO")
        canvas.setStrokeColor(LINHA); canvas.line(2 * cm, altura - 1.65 * cm, largura - 2 * cm, altura - 1.65 * cm)
    canvas.setStrokeColor(LINHA); canvas.line(2 * cm, 1.6 * cm, largura - 2 * cm, 1.6 * cm)
    canvas.setFont("Helvetica", 8); canvas.setFillColor(CINZA)
    canvas.drawString(2 * cm, 1.15 * cm, f"Sistema de Balcão v{VERSAO}")
    canvas.drawRightString(largura - 2 * cm, 1.15 * cm, f"Página {doc.page}")
    canvas.restoreState()


def gerar():
    doc = SimpleDocTemplate(SAIDA, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=2.2 * cm,
                            bottomMargin=2.2 * cm, title=f"Manual de Uso - Loja de Envios v{VERSAO}",
                            author="Loja de Envios", subject="Manual operacional do Sistema de Balcão")
    doc.build(conteudo(), onFirstPage=moldura, onLaterPages=moldura)
    return SAIDA


if __name__ == "__main__":
    print(gerar())
