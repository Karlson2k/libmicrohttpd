This tutorial is aimed at developers who want to learn how they can add HTTP serving 
capabilities to their applications with the @emph{GNU libmicrohttpd} library,
abbreviated @emph{MHD}, and who do not know how to start. It tries to help these
developers to implement common basic HTTP serving tasks by discussing executable
sample programs implementing different features. 

The text is supposed to be a supplement to the API reference manual of 
@emph{GNU libmicrohttpd} and for that reason does not explain many of the parameters.
Therefore, the reader should always consult the manual to find the exact meaning
of the functions used in the tutorial. In the same sense, the tutorial seeks to
encourage the use of the @emph{RFCs}, which document the conventions the Internet
is built upon. 

@emph{GNU libmicrohttpd} is assumed to be already installed and it has been
written with respect to version @value{VERSION}. As the library is still in its 
beta stages, later versions may show different behaviour. At the time being, 
this tutorial has only been tested on @emph{GNU/Linux} machines even though
efforts were made not to rely on anything that would prevent the samples from being
built on similar systems.
