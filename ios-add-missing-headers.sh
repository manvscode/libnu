#!/bin/bash

export IOS_SDK_VERSION=7.1
export SIM_PATH=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator${IOS_SDK_VERSION}.sdk
export IOS_PATH=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS${IOS_SDK_VERSION}.sdk


for file in usr/include/netinet/ip.h \
			usr/include/netinet/in_systm.h \
			usr/include/netinet/ip_icmp.h \
			usr/include/netinet/ip_var.h \
			usr/include/netinet/udp.h; do

	if [ -f "${SIM_PATH}/${file}" ]; then
		sudo ln -f "${SIM_PATH}/${file}" "${IOS_PATH}/${file}"
	fi;
done;
ls -l $IOS_PATH/usr/include/netinet/*
