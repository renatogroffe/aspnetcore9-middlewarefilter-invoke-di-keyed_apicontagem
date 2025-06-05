using APIContagem.Models;
using Groffe.AspNetCore.ApiKeyChecking;
using Microsoft.AspNetCore.Mvc;

namespace APIContagem.Controllers;

[ApiController]
[Route("[controller]")]
[MiddlewareFilter(typeof(ApiKeyCheckingPipeline))]
public class ContadorController : ControllerBase
{
    private readonly static Lock ContagemLock = new();

    private readonly ILogger<ContadorController> _logger;
    private readonly IConfiguration _configuration;
    private readonly Contador _contador;

    public ContadorController(ILogger<ContadorController> logger,
        IConfiguration configuration,
        Contador contador)
    {
        _logger = logger;
        _configuration = configuration;
        _contador = contador;
    }

    [HttpGet]
    public ResultadoContador Get()
    {
        int valorAtualContador;
        using (ContagemLock.EnterScope())
        {
            _contador.Incrementar();
            valorAtualContador = _contador.ValorAtual;
        }
        _logger.LogInformation($"Contador - Valor atual: {valorAtualContador}");

        return new()
        {
            ValorAtual = _contador.ValorAtual,
            Local = _contador.Local,
            Kernel = _contador.Kernel,
            Mensagem = _configuration["Saudacao"],
            Framework = _contador.Framework
        };
    }
}