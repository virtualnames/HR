# Model

1.struct_util.py（Only focuses on the structure support of the fields）

```shell
python struct_util.py
```

The output JSON file contains:

Fully supported: A field successfully converts in all certificates from a given tool;

Fully unsupported: A field fails in all certificates from a given tool;

Partially supported: A field successfully and unsuccessfully converts in all certificates from a given tool.

The field will appear in both the supported and unsupported sections, but the unsupported section will be marked with "Field name: Unrecognized."

2.content_util.py（focuses on field content processing errors and complements struct_util.py）

Collect errors that occur when different tools process the same certificate field content.

```sh
python content_util.py
```



(Ps: Both need to use the corresponding files generated during test case generation and ring testing)

