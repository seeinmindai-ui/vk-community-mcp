# Происхождение расширенного каталога

Метаданные vk_mcp/methods.json перенесены из alexfisenkov/vk-mcp, commit 1ca3b0b4be8cbe7ce23984f3d209416107440554, src/catalog/methods.json. Runtime/авторизация реализованы отдельно.

MIT License

Copyright (c) 2026 Alexander Fisenkov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


# Third-party sources

VK API parameter metadata is adapted from VKCOM/vk-api-schema commit
333481bd082ad747d4873ef4a77f9247097eeef0. The following upstream notice applies:

MIT License

Copyright (c) 2016 VK.com

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Research references

The following MIT projects informed scenario coverage and transport comparison;
their login/server/runtime implementations are not vendored in this repository:

- bulatko/vk-mcp-server — 5d723a247628daab3eef0d2259ab34be8d3d0868
- ilyautov/vk-mcp-ru — bfbeae72c83866e7331632eb6de499d7a0643e7f
- ssm82/full-vk-mcp — be6c21d6b6f701494840f139ae51574d87eba85a

MCP, Zod and build dependencies are listed and pinned by package-lock.json.
Their original licenses remain in their distributed packages.
