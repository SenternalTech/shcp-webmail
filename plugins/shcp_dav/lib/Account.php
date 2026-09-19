<?php
// SPDX-License-Identifier: MIT
namespace Shcp\Webmail\Dav;

/** Replace only the SHCP account's transport; every href is checked at the last HTTP boundary. */
final class Account extends \MStilkerich\CardDavClient\Account
{
    public function __construct(string $discovery,private Transport $transport,private array $auth,private \Closure $fence)
    {
        $transport->assertDavUrl($discovery);
        parent::__construct($discovery,[]);
    }
    public function getClient(?string $baseUrl=null): \MStilkerich\CardDavClient\CardDavClient
    {
        return new Client($baseUrl??$this->getUrl(),$this->transport,$this->auth,$this->fence);
    }
    public function setUrl(string $url): void
    {
        if (rtrim($url,'/')!==$this->transport->origin()) $this->transport->assertDavUrl($url);
        parent::setUrl($url);
    }
    public function jsonSerialize(): array
    {
        // Library diagnostic serialization must never reveal credentials.
        return ['discoveryUri'=>$this->getDiscoveryUri()];
    }
}
final class Client extends \MStilkerich\CardDavClient\CardDavClient
{
    public function __construct(string $base,Transport $transport,array $auth,\Closure $fence)
    {
        $this->base_uri=rtrim($base,'/').'/';
        $this->httpClient=new Adapter($base,$transport,$auth,$fence);
    }
}
final class Adapter extends \MStilkerich\CardDavClient\HttpClientAdapter
{
    public function __construct(string $base,private Transport $transport,private array $auth,private \Closure $fence)
    {
        parent::__construct($base,[]);
    }
    public function sendRequest(string $method,string $uri,array $options=[]): \Psr\Http\Message\ResponseInterface
    {
        ($this->fence)();
        $url=\Sabre\Uri\resolve($this->baseUri,$uri);
        $this->transport->assertDavUrl($url);
        $r=$this->transport->request($method,$url,$options['headers']??[],(string)($options['body']??''),$this->auth);
        return new \GuzzleHttp\Psr7\Response($r['status'],$r['headers'],$r['body']);
    }
}