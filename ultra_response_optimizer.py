"""
10x ULTRA RESPONSE OPTIMIZER
Response compression, headers optimization, and template minification
"""

from flask import make_response, request
import gzip
import io
import re
from functools import wraps

# 10x ULTRA: Response optimization decorator
def ultra_optimize_response(func):
    """10x ULTRA: Decorator to optimize all responses for maximum speed"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Execute the original function
        response = make_response(func(*args, **kwargs))
        
        # 10x ULTRA: Add performance headers
        response.headers['Cache-Control'] = 'public, max-age=300'  # 5 minute cache
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        
        # 10x ULTRA: Enable compression for text responses
        if (response.mimetype.startswith('text/') or 
            response.mimetype in ['application/javascript', 'application/json']):
            
            # Check if client accepts gzip
            if 'gzip' in request.headers.get('Accept-Encoding', ''):
                # Compress response
                if hasattr(response, 'data') and response.data:
                    compressed_data = ultra_gzip_compress(response.data)
                    response.data = compressed_data
                    response.headers['Content-Encoding'] = 'gzip'
                    response.headers['Content-Length'] = len(compressed_data)
        
        # 10x ULTRA: Minify HTML responses
        if response.mimetype == 'text/html':
            if hasattr(response, 'data') and response.data:
                minified_html = ultra_minify_html(response.data.decode('utf-8'))
                response.data = minified_html.encode('utf-8')
                response.headers['Content-Length'] = len(response.data)
        
        return response
    return wrapper

def ultra_gzip_compress(data):
    """10x ULTRA: Ultra-fast GZIP compression"""
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        buffer = io.BytesIO()
        with gzip.GzipFile(fileobj=buffer, mode='wb', compresslevel=6) as gzip_file:
            gzip_file.write(data)
        
        return buffer.getvalue()
    except Exception:
        return data

def ultra_minify_html(html_content):
    """10x ULTRA: Aggressive HTML minification"""
    try:
        # Remove HTML comments (but keep IE conditionals)
        html_content = re.sub(r'<!--(?!\[if).*?-->', '', html_content, flags=re.DOTALL)
        
        # Remove extra whitespace between tags
        html_content = re.sub(r'>\s+<', '><', html_content)
        
        # Remove extra whitespace in attributes
        html_content = re.sub(r'\s+', ' ', html_content)
        
        # Remove leading/trailing whitespace from lines
        lines = html_content.split('\n')
        lines = [line.strip() for line in lines if line.strip()]
        
        return '\n'.join(lines)
    except Exception:
        return html_content

# 10x ULTRA: Critical CSS for instant loading
ULTRA_CRITICAL_CSS = """
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;padding:0;background:#f8f9fa;overflow-x:hidden}
.navbar{background:#8B5CF6!important;box-shadow:0 2px 4px rgba(0,0,0,.1)}
.sidebar{background:#2d3748;min-height:100vh;position:fixed;top:0;left:0;width:250px;z-index:1000}
.main-content{margin-left:250px;padding:20px;min-height:100vh}
.card{border:none;box-shadow:0 2px 8px rgba(0,0,0,.1);margin-bottom:1rem;border-radius:.5rem}
.card-header{background:#8B5CF6;color:#fff;font-weight:600;border-radius:.5rem .5rem 0 0}
.btn-primary{background:#8B5CF6;border:#8B5CF6;transition:all .2s}
.btn-primary:hover{background:#7C3AED;border:#7C3AED;transform:translateY(-1px)}
.table{margin-bottom:0}
.nav-link{color:#e2e8f0!important;padding:.75rem 1rem;transition:all .2s}
.nav-link:hover{background:rgba(255,255,255,.1);color:#fff!important}
.nav-link.active{background:#8B5CF6;color:#fff!important}
.loading{display:none!important}
@media (max-width:768px){.sidebar{width:100%;height:auto;position:relative}.main-content{margin-left:0}}
</style>
"""

# 10x ULTRA: Critical JavaScript for instant interactivity
ULTRA_CRITICAL_JS = """
<script>
document.addEventListener('DOMContentLoaded',function(){
var l=document.querySelectorAll('.loading');
l.forEach(function(e){e.style.display='none'});
});
function ultraAjax(u,c){
var x=new XMLHttpRequest();
x.open('GET',u,true);
x.setRequestHeader('X-Requested-With','XMLHttpRequest');
x.onreadystatechange=function(){
if(x.readyState===4&&x.status===200){c(x.responseText);}
};
x.send();
}
</script>
"""

def inject_critical_resources():
    """10x ULTRA: Inject critical CSS/JS for instant loading"""
    return {
        'critical_css': ULTRA_CRITICAL_CSS,
        'critical_js': ULTRA_CRITICAL_JS
    }