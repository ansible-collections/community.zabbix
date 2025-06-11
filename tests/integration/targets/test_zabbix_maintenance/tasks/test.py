t1 = [{tag: ExampleHostsTag}, {tag: ExampleHostsTag2, value: ExampleTagValue}, {tag: ExampleHostsTag3, value: ExampleTagValue, operator: 0}]
t2 = [{ tag: ExampleHostsTag3, value: ExampleTagValue, operator: 0}, {tag: ExampleHostsTag}, {tag: ExampleHostsTag2, value: ExampleTagValue}]

s1 = sorted(t1, key=lambda k: (k["tag"], k.get("value", "")))
s2 = sorted(t2, key=lambda k: (k["tag"], k.get("value", "")))