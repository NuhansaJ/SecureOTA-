import sqlite3

conn = sqlite3.connect("verification_database.db")
cursor = conn.cursor()

cursor.execute("DELETE FROM device_hardware_binding")

conn.commit()
conn.close()
