from flask import Flask, jsonify
import sqlite3
from pathlib import Path

app = Flask(__name__)

def get_db_connection():
    db_path = Path(__file__).parent.joinpath('vulnerabilites_iot.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/donnees', methods=['GET'])
def get_donnees():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM vuln_iot')
    rows = cursor.fetchall()
    conn.close()
    result = [dict(row) for row in rows]
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
