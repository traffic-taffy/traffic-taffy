USER=wjhardaker

build:
	VERSION=$$(grep __VERSION__ ../traffic_taffy/__init__.py | sed 's/.* "//;s/".*//') ; \
	docker build -t $(USER)/traffic-taffy:latest -t $(USER)/traffic-taffy:$$VERSION .

publish:
	docker push wjhardaker/traffic-taffy:latest
