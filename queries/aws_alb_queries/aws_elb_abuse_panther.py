# Noflake ELBs
ELBS = ["app/web/dc4a02bad9c4ca52", "app/http-ingest-alb/7b4c775630dc2665"]

def rule(event):
    return event.udm("load_balancer_id") in ELBS

def title(event):
    return f"High number of errored requests [{event.get('request_count')}] to noflake ELBs from [{event.get('clientIp')}]"
