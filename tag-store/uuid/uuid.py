import uuid

def generate_uuid(version):
    if version == "1":
        return uuid.uuid1()
    if version == "4":
       return uuid.uuid4()
    else:
        raise ValueError("Unsupported UUID version")

output = str(generate_uuid(version))