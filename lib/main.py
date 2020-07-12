# #!../venv/bin/python
# from flask import Flask, jsonify, request, g
# import sqlite3
# import os

# app = Flask(__name__)

# db_file = os.path.abspath(os.path.dirname(__file__)) + '/todo_api.db'

# def get_db():
# 	db = getattr(g, '_database', None)
# 	if db is None:
# 		db = g._database = sqlite3.connect(db_file)
# 		db.row_factory = sqlite3.Row
# 	return db

# @app.teardown_appcontext
# def close_connection(exception):
# 	db = getattr(g, '_database', None)
# 	if db is not None: db.close()

# def query_db(query, args=(), one=False):
# 	cur = get_db().execute(query, args)
# 	rv = cur.fetchall()
# 	cur.close()
# 	return (rv[0] if rv else None) if one else rv

# def init_db():
# 	with app.app_context():
# 		db = get_db()
# 		with app.open_resource('flask_app.sql', mode='r') as f:
# 			db.cursor().executescript(f.read())
# 		db.commit()
# 		print ('init executed')

# #init_db()

# def get_all_tasks():
# 	sql = "select * from tasks"
# 	print (sql)
# 	db = get_db()
# 	rv = db.execute(sql)
# 	res = rv.fetchall()
# 	rv.close()
# 	tasks = []
# 	for row in res:
# 		task = {
# 			'id': row['id'],
# 			'title': row['title'],
# 			'description': row['description'],
# 			'done': row['done']
# 		}
# 		tasks.append(task)
# 	return (tasks)

# @app.route('/')
# def index():
# 	return('Welcome to Tasks API <a href="api/v1.0/tasks">Tasks</>')

# @app.route('/api/v1.0/tasks', methods=['GET'])
# def get_tasks():
#     tasks = get_all_tasks()
#     return (jsonify({'tasks': tasks}))

# @app.route('/api/v1.0/tasks/<int:task_id>', methods=['GET'])
# def get_task(task_id):
# 	task = [task for task in get_all_tasks() if task['id'] == task_id]
# 	if len(task) == 0:
# 		abort(404)
# 	return jsonify({'task': task[0]})

# @app.route('/api/v1.0/tasks', methods=['POST'])
# def create_task():
# 	if not request.json or not 'title' in request.json:
# 		abort(400)

# 	sql = "INSERT INTO tasks (title, description, done) VALUES ('%s', '%s', %d)" %(request.json['title'], request.json.get('description',""), int(request.json.get('done',0) ))
# 	#tasks.append(task)
# 	print (sql)
# 	db = get_db()
# 	db.execute(sql)
# 	res = db.commit()
# 	print( res )
# 	return "Inserted", 201
# 	#return jsonify({'task': task}), 201


# @app.route('/api/v1.0/tasks/<int:task_id>', methods=['PUT'])
# def update_task(task_id):
# 	task = [task for task in get_all_tasks() if task['id'] == task_id]
# 	if len(task) == 0:
# 		abort(404)
# 	if not request.json:
# 		abort(400)
# 	if 'title' in request.json and type(request.json['title']) != str:
# 		abort(400)
# 	if 'description' in request.json and type(request.json['description']) is not str:
# 		abort(400)
# 	if 'done' in request.json and type(request.json['done']) is not bool:
# 		abort(400)
# 	task[0]['title'] = request.json.get('title', task[0]['title'])
# 	task[0]['description'] = request.json.get('description', task[0]['description'])
# 	task[0]['done'] = request.json.get('done', task[0]['done'])
# 	return jsonify({'task': task[0]})

# @app.route('/api/v1.0/tasks/<int:task_id>', methods=['DELETE'])
# def delete_task(task_id):
# 	task = [task for task in get_all_tasks() if task['id'] == task_id]
# 	if len(task) == 0:
# 		abort(404)
# 	tasks.remove(task[0])
# 	return jsonify({'result': True})


# if __name__ == '__main__':
# 	app.run(debug=True)