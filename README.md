<h1>MicroProxy</h1>
Ferramenta simplificada, versátil e portátil de Proxy Reverso para uso em múltiplos 
propósitos (atualmente apenas solicitações Web e API em HTTP ou HTTPS).

<h2>Introdução</h2>
<p>MicroProxy surgiu como uma pequena ferramenta para contornar a limitação do kestrel 
em permitir apenas uma aplicação por porta de rede por IP, sem a necessidade de usar 
o IIS, que não permite a compilação de projetos em arquivo único, gerando pacotes de 
aplicações extremamente confusos com muitos arquivos adicionais em comparação ao modo 
de arquivo único.</p>
<p>Após uma determinada etapa de desenvolvimento do projeto, foi percebido que a 
ferramenta estava se aproximando do comportamento de um Proxy Reverso, mas o projeto 
já estava bastante avançado para ser cancelado e foi continuado para fins de estudos e 
completa personalização a todas as necessidades que foram surgindo.</p>

A ferramenta foi desenvolvida em ASP.NET 8 na linguagem C#, sem a necessidade de 
instalação (portátil), a não ser instalar o Runtime do ASP.NET Core 8.0.

<a href="https://dotnet.microsoft.com/pt-br/download/dotnet/8.0">Baixar .NET 8.0</a>

Por hora apenas foi testado em Windows, mas o código também pode ser compilado para 
Linux e Mac.
