SUGAR=sugar
SOURCES=watchdog.spy
PY_MODULE=watchdog.py
PREFIX=/usr/local

dist:
	$(SUGAR) -clpy $(SOURCES) | grep -v $(PY_MODULE) > $(PY_MODULE) 
	chmod +x $(PY_MODULE)

doc:
	kiwi MANUAL.txt MANUAL.html

install:dist
	cp $(PY_MODULE) $(PREFIX)/bin/do

clean:
	rm _*.py *.pyc


