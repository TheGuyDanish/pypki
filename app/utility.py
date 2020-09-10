from OpenSSL import crypto

def has_extension(cert, extension):
    """
    Search a provided X509 certificate for a provided extension.

    Arguments: cert - The certificate, must be an OpenSSL.crypto.X509 object
               extension - The extension to look for, must be a string.
    Returns:   boolean
    Example:   has_extension(intcert, 'subjectKeyIdentifier')
    """
    extensions = []
    num_extensions = cert.get_extension_count()
    for num in range(0, num_extensions):
        ext = cert.get_extension(num)
        ext_name = ext.get_short_name().decode("UTF-8")
        extensions.append(ext_name)
    if extension in extensions:
        return True
    else:
        return False