FROM python:3.7

RUN apt update -y

RUN apt -y install libxml2-dev libxslt-dev git vim

WORKDIR /harpoon

ADD . .

RUN pip3 install .

RUN mkdir -p ~/.config/harpoon

RUN mv harpoon/data/harpoon_keys.conf ~/.config/harpoon/config