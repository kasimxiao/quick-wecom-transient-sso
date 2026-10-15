"""Helpers for disposable loopback-only protocol tests, never production."""
import base64
import json
import http.cookiejar
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*_):return None


class LoopbackPolicy(http.cookiejar.DefaultCookiePolicy):
    """Permit secure cookies over HTTP only for this disposable loopback origin."""
    def __init__(self,origin):super().__init__();self.origin=origin
    def return_ok_secure(self,cookie,request):
        return request.full_url.startswith(self.origin+'/') or super().return_ok_secure(cookie,request)


def claims(token):
    """Inspect locally issued claims; never log raw tokens."""
    part=token.split('.')[1];return json.loads(base64.urlsafe_b64decode(part+'='*(-len(part)%4)))
