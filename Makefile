app:
	python3 setup.py build_ext -i
	pip3 install .
clean:
	rm -rf *.a *.o *.so *.so.* *.d build/
