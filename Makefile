#  LittleSDK Bootstrapping
KIT_PATH=deps/littlesdk
KIT_REPO=sebastien/littlesdk
include $(if $(KIT_PATH),$(shell test ! -e "$(KIT_PATH)/setup.mk" && git clone git@github.com:$(KIT_REPO).git "$(KIT_PATH)";echo "$(KIT_PATH)/setup.mk"))
# EOF

