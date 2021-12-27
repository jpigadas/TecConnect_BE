from init import app

if __name__ == '__main__':
    #app.run(host="0.0.0.0", port=5000, debug=True)
    # run app in debug mode on port 8000
    app.run(debug=True, port=5000)
