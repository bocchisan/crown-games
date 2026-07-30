# subscription — План сборки

Первый не-`DONE` этап — текущий. DoD/тесты — `docs/spec.md` + `crown-spec/docs/01-standards.md`.
Не заморожена. Подписка — **использование формы `stream`** (без канистры/резолвера): вся ончейн-логика
в форме `stream` (`crown-factory`, этап P7 общего плана); здесь — параметры и e2e.

| Этап | Что | Статус |
|---|---|---|
| S0 | Скелет: `docs/` + `e2e/`-драйвер, CI; границы (нет канистры/резолвера/threshold) | DONE |
| Sf | **Форма `stream`** (`crown-factory`): `salt/stream.rs` + Anchor-программа `create_escrow`/`release`/`cancel`/`refund` через сплиттер | DONE¹ |
| S1 | E2e через devnet: `create_escrow` → `release(k)` по порядку по расписанию (permissionless) → `cancel` подписью донора / `refund()` по просрочке | DONE² |
| S2 | Прод-деплой (форма `stream` — из `crown-factory` P7) | TODO |

Форма `stream` (расписание, распределение куска, `cancel` подписью донора, `refund()`) реализуется в
`crown-factory`; подписка её только применяет. Голосовых/подписных/канистерных инвариантов нет.

¹ Sf: `crown-salt::stream` — байт-точная соль (`donor‖K‖recipients‖shares‖chunk‖n_chunks‖t0‖period‖fee_bps‖fee_wallet‖nonce`, без резолвера; 4 теста, clippy/fmt чисто). Anchor-программа `shapes/stream/solana` (по конвенциям `two-outcome`): `create_escrow` (соль=on-chain hashv==crown-salt; валидация строки — 1≤K≤6, уникальность, Σshares≤10000, ≥1 ненулевая, piece≥MIN_GROSS; фонд `chunk·n_chunks`); `release(k)` permissionless, гейт `!settled ∧ k==released ∧ now≥t0+k·period`, распределение через сплиттер per-recipient (ATA в `remaining_accounts`), Σ комиссий→fee_wallet, пыль→донору, точный баланс `Σnet+Σfee+пыль==chunk`, последний кусок→`settled`+закрытие vault; `cancel` — ed25519-подпись донора над `CANCEL_DOMAIN‖program_id‖escrow‖0x01` (интроспекция sysvar), остаток→донору; `refund()` — permissionless после `t0+released·period+RELEASE_MARGIN`. **`cargo check` чисто** (0 ошибок; предупреждения — anchor-macro baseline, как у two-outcome). **Рантайм-тесты (litesvm) написаны** — `shapes/stream/solana/tests/lifecycle.rs`, 12 тестов (create/refund/пыль-не-блокирует/cancel/отбой-чужой-подписи/release-через-сплиттер + отказные реверты: не-в-черёд/до-срока/после-settled, refund-до-просрочки, salt-mismatch, мульти-получатель по долям), зелёные, clippy (флаги CI) чисто; требуют `cargo build-sbf`.

² S1: stream-программа задеплоена на **Solana devnet** (`81HsKu3FCjzJvuqb8fWQTD4Khc9qSq98CC7Y967Nfnm9`, upgrade-authority — донор). E2e-драйвер `e2e/` (`subscription-e2e`, `RpcClient` на `api.devnet.solana.com`, донор `crown-index-e2e-donor`) прогнал **вживую** все три пути с реальным тест-USDC (`4zMMC9sr…`): (1) `release` полного расписания — каждый кусок через сплиттер получателю (net) + комиссия fee_wallet, последний → `settled`+закрытие vault (получатель 1.94 USDC, комиссия 0.06 при chunk=1 USDC, n=2, fee 3%); (2) `cancel` подписью донора → весь остаток донору; (3) `refund()` permissionless после margin → остаток донору. Балансы сверены on-chain, все tx подтверждены. Осталось S2 — прод/mainnet-деплой (реальный Circle USDC).

**Путь (3) однажды разошёлся с формой, и это стоит помнить.** Драйвер создавал `t0` далеко в прошлом,
чтобы сразу попасть в окно возврата; форма позже получила защиту `BornRefundable` — поток нельзя родить
уже просроченным (`t0` не старше `RELEASE_MARGIN`). Прогон упал, а строка «S1 DONE» какое-то время
оставалась и читалась как правда. Границы создания и возврата сходятся **ровно в одной точке**
(`t0 = now − RELEASE_MARGIN`), поэтому единственный живой способ дойти до `refund` — встать вплотную к
границе и дать реальному времени её пересечь: драйвер берёт запас в 90 с и ждёт его. Мораль общая:
живой прогон, который перестали запускать, стареет молча.
