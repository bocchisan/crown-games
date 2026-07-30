# auction — План сборки

Первый не-`DONE` этап — текущий. DoD/тесты — `docs/spec.md` + `crown-spec/docs/01-standards.md`.
Контракт игр — `games-harness.md`. Не заморожена.

| Этап | Что | Статус |
|---|---|---|
| A0 | Скелет: `logic/`+`canister/`, CI, границы (нет сетей, нет таймеров) | DONE |
| A1 | `logic/` — машина (`Bidding→Performing→Voting→Done`, `pick_winner`), подсчёт голосов (two-outcome), правило дедлайна, `resolve` per-entry + тесты | DONE¹ |
| A2 | Канистра: `create_auction` (ленивая, permissionless); `register_entry` — пруф рождения, per-entry резолвер `key([entry_id])`; `accept_lot`/`return_lot`/`return_entry`/`cancel_auction`; набор эскроу на лот | DONE² |
| A3 | **Выбор победителя получателем** (`pick_winner` из принятых лотов) + двухступенчатый борд («заявлено» вне канистры, отсечка `T`) | DONE³ |
| A4 | Голосование весом книги (валидность в `inspect_message`, дедуп, `V_MAX`); вердикт: per-entry резолвер, оплаченный pull, мемоизация подписи | DONE⁴ |
| A4.5 | **Выравнивание по эталону (`P6.6`):** платный `push_root` + кеш `ROOTS`; пруфы рождения и веса — против кеша, BLS только на `push_root`; `full_e2e` до реальной threshold-подписи | DONE⁵ |
| A5 | E2e через реальную сеть: аукцион → ставки → приём → выбор → голос → расчёт/возвраты | DONE⁶ |
| A6 | Прод-деплой | TODO |

DoD не-отрицательности (`cost.md §6`): A2 — `register_entry` без пруфа рождения не растит память,
«заявлено» вне канистры; A3 — выбор победителя, не скан/таймер; A4 — нулевой голос не доходит до `update`,
повтор `request_signature` на разрешённом вкладе бесплатен (подпись из хранилища, ключ — `entry_id`).

¹ A1: `logic/` zero-dep, форма `two-outcome`. **Машина** `Bidding→Performing{winner_lot}→Voting{started_at}→Done{winner:opt Outcome}`: время до действия; `Bidding` не имеет временного перехода (приём заморожен гейтом на `T=created_at+duration`, но состояние держится, пока получатель не `pick_winner`/`cancel`); `Performing→Done{Cancel}` при `created_at+duration+perform_window`; `Voting→Done{verdict}` при `started_at+voting_period`; overflow не двигает состояние; `Done` — поглощающее. `pick_winner(lot)` — только из `Bidding` по принятому не-возвращённому лоту → `Performing{lot}`. `return_lot` победителя в `Performing`→`Done{Cancel}`; проигравший лот в `Performing` не возвращается. **Вердикт** two-outcome (`Σdone>Σnot` строго, иначе/overflow→Cancel; property-тест). **`resolve` (per-entry)**: возвращён вклад→Cancel; возвращён лот→Cancel; иначе по состоянию×`is_winner_lot`. **Правило дедлайна** (`checked`, включительно). Канистра лоты не суммирует и не сканирует — победителя называет получатель. Общая крипта — из `crown-games-common` при A2.

² A2: канистра на `crown-games-common` (BLS-пруф/threshold-резолвер/PDA/подпись/парсинг — общие). `create_auction` — чистое эхо деривации (recipient-подписант, ноль записи): пересчитывает `auction_id` и сверяет с подписанным. `register_entry` (donor-подписант) — носитель материализации: `lot_id=sha256(auction_id‖text_hash)`, `entry_id=sha256(lot_id‖donor‖nonce‖gross‖deadline)` → резолвер `key([entry_id])` → адрес эскроу → **пруф рождения** локально; первый подтверждённый вклад материализует аукцион (валидация диапазонов, `created_at` из слота), затем добавляет вклад в лот с монотонным `seq` и `entry_id`. Гейты: `gross≥min_entry`, дедлайн-правило, долив в возвращённый лот → ✗, дубль-эскроу → ✗, приём заморожен на `T`. `accept_lot`/`return_lot`/`return_entry`/`cancel_auction`/`ready`/`pick_winner` — signature-gated по `recipient`. Queries `get_auction`/`get_lot`/`get_resolver(lot, donor, nonce, gross, deadline)`.

³ A3: **выбор победителя** — `pick_winner(lot)` (recipient-подписант) над принятым не-возвращённым лотом → `Performing{winner_lot}`. Ончейн-скана «кто дороже» нет; «самый дорогой» — рекомендация борда `crown-app` (слой вне канистры), а не правило канистры. Борд «заявлено» — вне периметра; отсечка `T=created_at+duration` — граница приёма пруфов (гейт в `register_entry`). Застрявший аукцион (не выбрали/не отменили) деньги не держит — `refund()` по `deadline`.

⁴ A4: `vote` — вес = репутация голосующего к получателю (свидетель книги против корня индекса); валидность (подпись+таргет+вес≥`MIN_VOTE_WEIGHT`) отбита бесплатно в `inspect_message`; запись через машину (только `Voting`, дедуп `(lot_id,voter)`, кэп `V_MAX=500`). `request_signature(chain, auction, lot, escrow)` — **трёхступенчатое разрешение** per-entry (`resolve`) → outcome; `NoVerdict`→`NotDecided` **без списания**; иначе списание `SIGN_PRICE` **перед** `sign_with_schnorr`; подпись `key([entry_id])` над `verdict_message` (форма two-outcome), проверяется on-chain против `resolver` эскроу — один вклад, одна подпись. Подпись **хранится** по `entry_id`: повтор отдаётся бесплатно до проверки оплаты, конкурентный запрос получает `SignInFlight`, `get_signature` — свободный `query`. Реальная threshold-подпись — на A5.

**Переработка на модель «получатель выбирает» (без финал-скана/`winner.rs`/`standing`/`beats`, per-entry резолвер):** канистра слепа к суммам (`gross` валидируется при регистрации и не хранится). 38 тестов (logic 17 + канистра 21), clippy strict/fmt/wasm/.did чисто.

⁵ A4.5: расщеплённое доверие к индексу — как у эталона. Добавлены `push_root(cert)` (оплаченный
пуш за `ROOT_PRICE`, кеш `ROOTS` глубины `ROOT_CACHE = 4`, повторный пуш освежает позицию и не растит
кеш), вариант `RootPushed`, `root_price` в `config/*.toml`. `admit_register_entry` и `voter_weight` больше **не** зовут
`birth::certified_root` — реконструируют свидетеля против кешированного корня (обход хеш-дерева,
O(log n)); `cert` ушёл из wire-формата обоих. Причина: две BLS-пары не влезают в 200M инструкций
`inspect_message`, то есть **валидная** регистрация не проходила бы вовсе. Закреплено гейтом CI
(«BLS only on the paid push_root»: ровно одно вхождение, внутри `push_root`). **+4 теста:**
`endpoint_e2e` — неоплаченный `push_root` не делает работы, оплаченный с кривым сертификатом отбит
(оплата не возвращается), `register_entry` со свидетелем без кеша корней отбит на границе;
**`full_e2e`** (новый файл + фикстура `e2e/mock-sol-rpc`) — мок SOL RPC → `index.ingest` →
сертифицированное рождение → `push_root` → `register_entry` **прямым ingress** → `Materialized` →
`cancel_auction` → `request_signature` → **реальная 64-байтная Ed25519 threshold-подпись** под
`key([entry_id])`, проходящая `verify_strict` против резолвера эскроу; повтор отдаётся из хранилища
бесплатно, `get_signature` — тем же байтам. **57 тестов** (logic 20 + канистра 28 + pocket-ic 9),
clippy strict/fmt/wasm/.did чисто.

⁶ A5: живой прогон **выполнен** на Solana devnet против локального PocketIC-стека (индекс + мок SOL RPC
+ релей-прокси + auction на `key_1`); драйвер — `e2e/a5`. Полный конкурс на настоящих деньгах: реальный
`splitter.donate` покупает голосующему **вес по книге** (единственный легальный путь, `00 §9`), два
реальных `create_escrow` по 2 тест-USDC в **двух лотах**, обе транзакции свёрнуты индексом в рождения,
оплаченный `push_root` → два `register_entry` **прямым ingress** (материализация + долив) →
`accept_lot` обоих → `pick_winner` → `ready` → **голос** весом 0.5 USDC против кешированного корня →
окно закрылось → два оплаченных `request_signature`: победитель `settle`, проигравший `cancel` — две
настоящие threshold-подписи под **разными** листовыми резолверами, каждая проверена `verify_strict`
против поля `resolver` своего эскроу. На devnet: `claim(settle)` → получателю `net`, кошельку комиссии
`fee`; `claim(cancel)` → донору весь `gross`; оба vault закрыты. Замыкание петли: сеттлмент свёрнут
обратно — репутация легла на **донора**, на адресе эскроу ноль.

Побочно закрыты два плейсхолдера, без которых прогон невозможен: **якорь slot→unix**
(`genesis_slot`/`genesis_unix`, замерен `getBlockTime` финализованного слота — с нулём `created_at`
уезжает в 1975 год и окно приёма закрыто до первой регистрации) и devnet-кошелёк комиссии. Дрейф якоря
драйвер проверяет **до** того, как двинутся деньги, и на превышении печатает готовые строки конфига.
Непокрытый шов тот же, что у эталона — многопровайдерный RPC-консенсус (`A6`).
