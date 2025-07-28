"""
10x ULTRA FRONTEND PERFORMANCE OPTIMIZER
CSS, JavaScript, and Template compression for maximum speed
"""

import re
import gzip
import io
from functools import lru_cache

# 10x ULTRA: CSS minification patterns
CSS_MINIFY_PATTERNS = [
    (r'/\*.*?\*/', ''),  # Remove comments
    (r'\s+', ' '),       # Multiple spaces to single
    (r';\s*}', '}'),     # Remove semicolon before }
    (r'{\s*', '{'),      # Remove space after {
    (r'}\s*', '}'),      # Remove space after }
    (r':\s*', ':'),      # Remove space after :
    (r';\s*', ';'),      # Remove space after ;
    (r',\s*', ','),      # Remove space after ,
]

# 10x ULTRA: JavaScript minification patterns
JS_MINIFY_PATTERNS = [
    (r'//.*?\n', '\n'),     # Remove line comments
    (r'/\*.*?\*/', ''),     # Remove block comments
    (r'\s+', ' '),          # Multiple spaces to single
    (r';\s*\n', ';'),       # Remove newlines after semicolon
    (r'{\s*', '{'),         # Remove space after {
    (r'}\s*', '}'),         # Remove space after }
    (r':\s*', ':'),         # Remove space after :
    (r';\s*', ';'),         # Remove space after ;
    (r',\s*', ','),         # Remove space after ,
]

@lru_cache(maxsize=1000)
def ultra_minify_css(css_content):
    """10x ULTRA: Aggressive CSS minification with caching"""
    try:
        minified = css_content
        for pattern, replacement in CSS_MINIFY_PATTERNS:
            minified = re.sub(pattern, replacement, minified, flags=re.DOTALL)
        return minified.strip()
    except Exception:
        return css_content

@lru_cache(maxsize=1000) 
def ultra_minify_js(js_content):
    """10x ULTRA: Aggressive JavaScript minification with caching"""
    try:
        minified = js_content  
        for pattern, replacement in JS_MINIFY_PATTERNS:
            minified = re.sub(pattern, replacement, minified, flags=re.DOTALL)
        return minified.strip()
    except Exception:
        return js_content

@lru_cache(maxsize=500)
def ultra_compress_html(html_content):
    """10x ULTRA: Aggressive HTML compression with caching"""
    try:
        # Remove comments
        html_content = re.sub(r'<!--.*?-->', '', html_content, flags=re.DOTALL)
        
        # Remove extra whitespace between tags
        html_content = re.sub(r'>\s+<', '><', html_content)
        
        # Remove leading/trailing whitespace from lines
        lines = html_content.split('\n')
        lines = [line.strip() for line in lines if line.strip()]
        
        return '\n'.join(lines)
    except Exception:
        return html_content

def ultra_gzip_compress(content):
    """10x ULTRA: GZIP compression for responses"""
    try:
        if isinstance(content, str):
            content = content.encode('utf-8')
        
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode='wb', compresslevel=9) as gzip_file:
            gzip_file.write(content)
        
        return buffer.getvalue()
    except Exception:
        return content

# 10x ULTRA: Performance-optimized template filters
ULTRA_PERFORMANCE_CSS = """
/* 10x ULTRA: Critical path CSS - inline for maximum speed */
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;padding:0;background:#f8f9fa}
.navbar{background:#8B5CF6!important;box-shadow:0 2px 4px rgba(0,0,0,.1)}
.card{border:none;box-shadow:0 2px 8px rgba(0,0,0,.1);margin-bottom:1rem}
.btn-primary{background:#8B5CF6;border:#8B5CF6}
.btn-primary:hover{background:#7C3AED;border:#7C3AED}
.table{margin-bottom:0}
.sidebar{background:#2d3748;min-height:100vh}
.nav-link{color:#e2e8f0!important;padding:.75rem 1rem}
.nav-link:hover{background:rgba(255,255,255,.1);color:#fff!important}
.nav-link.active{background:#8B5CF6;color:#fff!important}
"""

ULTRA_PERFORMANCE_JS = """
// 10x ULTRA: Critical path JavaScript - inline for maximum speed
document.addEventListener('DOMContentLoaded',function(){
var loadingElements=document.querySelectorAll('.loading');
loadingElements.forEach(function(el){el.style.display='none'});
});
function ultraFastAjax(url,callback){
var xhr=new XMLHttpRequest();
xhr.open('GET',url,true);
xhr.setRequestHeader('X-Requested-With','XMLHttpRequest');
xhr.onreadystatechange=function(){
if(xhr.readyState===4&&xhr.status===200){
callback(xhr.responseText);
}};
xhr.send();
}
"""

def inject_ultra_performance_assets():
    """10x ULTRA: Inject critical CSS/JS inline for maximum speed"""
    return {
        'critical_css': ultra_minify_css(ULTRA_PERFORMANCE_CSS),
        'critical_js': ultra_minify_js(ULTRA_PERFORMANCE_JS)
    }