from pathlib import Path

def jinja(expr):
    return chr(123) + chr(123) + ' ' + expr + ' ' + chr(125) + chr(125)


def jinjatag(expr):
    return chr(123) + '%' + ' ' + expr + ' ' + '%' + chr(125)


def write_template(path, lines):
    Path(path).write_text('\n'.join(lines) + '\n', encoding='utf-8')

layout_lines = [
    '<!doctype html>',
    '<html lang= fr>',
    '<head>',
    '  <meta charset=utf-8>',
    '  <title>Archipel Web</title>',
    '  <link rel=stylesheet href= + jinja(url_for(static, filename=style.css)) + >',
    '</head>',
    '<body>',
    '  <header>',
    '    <strong>Archipel Sprint 4</strong>',
    '    <nav>',
    '      <a href= + jinja(url_for(index)) + >Accueil</a>',
    '      <a href= + jinja(url_for(share)) + >Partager</a>',
    '      <a href= + jinja(url_for(download)) + >Télécharger</a>',
    '      <a href= + jinja(url_for(chat)) + >Chat</a>',
    '    </nav>',
    '  </header>',
    '  <main>',
    '    ' + jinjatag('block content'),
    '    ' + jinjatag('endblock'),
    '  </main>',
    '</body>',
    '</html>',
]

index_lines = [
    '  <section>',
    '    <h1>Bienvenue sur Archipel Web</h1>',
    '    <p>Utilise les boutons ci-dessus pour démarrer un partage, récupérer un manifeste ou envoyer un message chiffré.</p>',
    '  </section>',
]

share_lines = [
    '  <section>',
    '    <h2>Partager un fichier</h2>',
    '    <form method=post>',
    '      <label>Chemin du fichier (relatif)</label>',
    '      <input name=filepath placeholder=demo/tmp_sprint3_test/ton_doc.docx required>',
    '      <label>Port TCP</label>',
    '      <input name=port type=number value=7902>',
    '      <button>Lancer le nœud</button>',
    '    </form>',
    '    ' + jinjatag('if message'),
    '      <p class=status>' + jinja('message') + '</p>',
    '    ' + jinjatag('endif'),
    '  </section>',
]

download_lines = [
    '  <section>',
    '    <h2>Télécharger un fichier</h2>',
    '    <form method=post>',
    '      <label>Manifeste JSON (relatif)</label>',
    '      <input name=manifest placeholder=manifests/xxxx.json required>',
    '      <label>Port du nœud</label>',
    '      <input name=port type=number value=7902>',
    '      <label>Attente en secondes</label>',
    '      <input name=wait type=number value=10>',
    '      <label>Répertoire de sortie</label>',
    '      <input name=output value=demo/tmp_sprint3_test/downloads>',
    '      <label>Transport</label>',
    '      <select name=transport>',
    '        <option value=tcp>tcp</option>',
    '        <option value=udp>udp</option>',
    '      </select>',
    '      <button>Télécharger</button>',
    '    </form>',
    '    ' + jinjatag('if message'),
    '      <p class=status>' + jinja('message') + '</p>',
    '    ' + jinjatag('endif'),
    '  </section>',
]

chat_lines = [
    '  <section>',
    '    <h2>Envoyer un message</h2>',
    '    <form method=post>',
    '      <label>Peer ID (hex)</label>',
    '      <input name=peer_id placeholder=abcd1234... required>',
    '      <label>Message</label>',
    '      <input name=text placeholder=Salut required>',
    '      <label>Port local</label>',
    '      <input name=port type=number value=7901>',
    '      <label>Port peer</label>',
    '      <input name=peer_port type=number value=7902>',
    '      <label>Attente (s)</label>',
    '      <input name=wait type=number value=12>',
    '      <button>Envoyer</button>',
    '    </form>',
    '    ' + jinjatag('if message'),
    '      <p class=status>' + jinja('message') + '</p>',
    '    ' + jinjatag('endif'),
    '  </section>',
]

write_template('web/templates/layout.html', layout_lines)
write_template('web/templates/index.html', index_lines)
write_template('web/templates/share.html', share_lines)
write_template('web/templates/download.html', download_lines)
write_template('web/templates/chat.html', chat_lines)
