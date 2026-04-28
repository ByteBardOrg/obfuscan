# exec(base64.b64decode(...))

This is the most common shape in the Datadog malicious-software-packages
dataset for the PyPI ecosystem. The real samples decode to credential
exfiltration loaders. Our blob decodes to `print("stub")`.

Reference: https://github.com/DataDog/malicious-software-packages-dataset
