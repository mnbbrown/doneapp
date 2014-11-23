from doneapp import app

if app.config['DEBUG']:
    app.debug = True

app.run()