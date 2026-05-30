rule PythonSourceCode
{
    meta:
        category = "source_code"
        confidence = "0.85"
   strings:
        $import_str = "import "
        $def_str = "def "
        $class_str = "class "
        $return_str = "return"
        $if_name_str = "if __name__"

    condition:
        3 of them
}

rule GenericConfig
{
    meta:
        category = "credentials"
        confidence = "0.80"
   strings:
        $password_str = "password ="
        $secret_str = "secret ="
        $api_key_str = "api_key ="
        $token_str = "token ="

    condition:
        any of them
}