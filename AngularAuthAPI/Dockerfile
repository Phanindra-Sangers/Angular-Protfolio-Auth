FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY *.csproj . 
RUN dotnet restore 
COPY . .
RUN dotnet build    -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "/src"  -o /app/publish 

FROM base AS final
WORKDIR /app
ENV ASPNETCORE_ENVIRONMENT=Development
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "AngularAuthAPI.dll"]
