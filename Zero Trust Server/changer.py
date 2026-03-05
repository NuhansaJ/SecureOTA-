import sqlite3
p = r"e:\SecureOTA\Zero Trust Server\verification_database.db"
conn = sqlite3.connect(p)
cur = conn.cursor()
cur.execute("UPDATE device_identity SET status = 'active'")
conn.commit()
conn.close()