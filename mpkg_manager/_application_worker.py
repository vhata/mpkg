"""Fixed private application worker; credentials are read only from stdin."""
import http.client
import json
import os
from pathlib import Path
import resource
import sys

# Fixed trusted sibling imports under isolated Python, never request paths.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mpkg_manager._runtime_proc import ProcReader

MAX_BODY = 65536


def predicate_result(application, body, root_id, root_path, sentinel):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result
    value = json.loads(body, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    if application == "sonarr":
        return type(value) is dict and value.get("status") == "OK"
    return (type(value) is dict and type(value.get("id")) is int
            and value["id"] == root_id and value.get("path") == root_path
            and value.get("accessible") is True
            and type(value.get("unmappedFolders")) is list
            and any(type(row) is dict and row.get("name") == sentinel
                    and row.get("path") == root_path + "/" + sentinel
                    for row in value["unmappedFolders"]))


def request(data, key):
    """Direct numeric loopback connection: no proxies, redirects or retries."""
    connection = http.client.HTTPConnection("127.0.0.1", data["port"], timeout=data["timeout"])
    try:
        path = data["base"] + ("/ping" if data["application"] == "sonarr" else
                f'/api/v3/rootfolder/{data["root_id"]}?timeout=true')
        connection.request("GET", path, headers={} if not key else {"X-Api-Key": key})
        response = connection.getresponse()
        if response.status != 200:
            return "failed"
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            return "unavailable"
        return "passed" if predicate_result(data["application"], body, data["root_id"],
                                              data["root_path"], data["sentinel"]) else "failed"
    finally:
        connection.close()


def main():
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        data = json.loads(sys.stdin.buffer.read(16385))
        fd = data["namespace_fd"]
        expected = tuple(data["namespace"])
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) != expected:
            raise ValueError
        own = os.stat("/proc/self/ns/net")
        if (own.st_dev, own.st_ino) != expected:
            os.setns(fd, os.CLONE_NEWNET)
        own = os.stat("/proc/self/ns/net")
        if (own.st_dev, own.st_ino) != expected:
            raise ValueError
        # Inspect in the held namespace before making any authenticated request.
        before = ProcReader().capture(tuple(data["pids"]), data["port"], lambda: None)
        result = request(data, data["key"])
        if ProcReader().capture(tuple(data["pids"]), data["port"], lambda: None) != before:
            result = "unavailable"
    except (Exception,):
        result = "unavailable"
    sys.stdout.write(json.dumps({"functional_result": result}))


if __name__ == "__main__":
    main()
