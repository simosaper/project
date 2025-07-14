import random, os
from datetime import datetime

def run(app):
    count = app.ask_count("How many Basic URLs to generate?")
    if not count:
        return
    filename = f"results/basic_urls_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, 'w') as f:
        for _ in range(count):
            ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
            domain = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5,12)))
            tld = random.choice(['.com', '.net', '.org'])
            url = random.choice([f"http://{ip}/", f"https://{domain}{tld}/"])
            f.write(url + '\n')
    app.log(f"✅ Generated {count} Basic URLs -> {filename}")
run(app)
