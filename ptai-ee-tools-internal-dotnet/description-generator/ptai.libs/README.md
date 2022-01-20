This is where PT AI viewer DLLs are to be placed. DLLs are:
- Repository.Description.dll - this is where issues description resources are stored. LZ4 packer used here (see MessagePack.dll)
- Messages.dll - IssueDescriptionBase and its descendants are implemented here 
- MessagePack.dll - LZ4MessagePackSerializer inplemented here
- Repository.Common.dll - internally used by Repository.Description.dll
- Utilities.Common - internally used by Messages.dll
