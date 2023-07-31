
basic_str = '{scheme}://{ip}:{port}/{path}'
words = []
for i in range(1, 255):
    words.append(basic_str.format(scheme = 'http', ip = '192.168.0.' + str(i), port = '8080', path = 'admin'))

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    for p in words:
        engine.queue(target.req, [p, ])

 
@FilterStatus(500)
def handleResponse(req, intr):
    table.add(req)
