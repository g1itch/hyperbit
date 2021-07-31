# Copyright 2021 HyperBit developers

from html.parser import HTMLParser

try:
    import lxml.etree
    from lxml.html import clean
except ImportError:
    clean = None

try:
    import markdown
    import pkg_resources
except ImportError:
    md = None
else:
    md_extensions = [
        ep.name for ep
        in pkg_resources.iter_entry_points('markdown.extensions')]
    md = markdown.Markdown(extensions=md_extensions)


class SimpleHtmlParser(HTMLParser):
    """This is solely for HTML detection."""

    has_html = False
    nonstd = False
    allow_tags = (
        'a', 'abbr', 'acronym', 'address', 'area', 'article', 'aside',
        'audio', 'b', 'big', 'blockquote', 'br', 'button',
        'canvas', 'caption', 'center', 'cite', 'code', 'col', 'colgroup',
        'command', 'datagrid', 'datalist', 'dd', 'del', 'details', 'dfn',
        'dialog', 'dir', 'div', 'dl', 'dt', 'em', 'event-source', 'fieldset',
        'figcaption', 'figure', 'footer', 'font', 'header', 'h1',
        'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'ins',
        'keygen', 'kbd', 'label', 'legend', 'li', 'm', 'map', 'menu', 'meter',
        'multicol', 'nav', 'nextid', 'ol', 'output', 'optgroup', 'option',
        'p', 'pre', 'progress', 'q', 's', 'samp', 'section', 'select',
        'small', 'sound', 'source', 'spacer', 'span', 'strike', 'strong',
        'sub', 'sup', 'table', 'tbody', 'td', 'textarea', 'time', 'tfoot',
        'th', 'thead', 'tr', 'tt', 'u', 'ul', 'var'
    )

    def handle_starttag(self, tag, attrs):
        if not self.has_html:
            if tag in ('img', 'video') or tag in self.allow_tags:
                self.has_html = True


class MessageCleaner():
    def __init__(self):
        self.cleaner = clean.Cleaner(
            links=False,
            # remove_tags=('img',),
            safe_attrs_only=True,
            # remove_unknown_tags=False,
            allow_tags=SimpleHtmlParser.allow_tags
        ) if clean else None
        self.html = False

    def clean_html(self, text):
        self.html = False
        if not self.cleaner:
            return text

        try:
            html = lxml.html.fromstring(
                text, parser=lxml.html.HTMLParser(recover=False))
        except lxml.etree.XMLSyntaxError:
            html = ''

        if not len(html):
            parser = SimpleHtmlParser()
            parser.feed(text)
            if not parser.has_html:
                if not md:
                    return text
                self.html = True
                return md.reset().convert(text)
                # parser.feed(text)
                # self.html = parser.has_html

        try:
            self.html = True
            return self.cleaner.clean_html(text)
        except lxml.etree.ParserError:
            return ''
